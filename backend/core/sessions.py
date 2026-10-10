"""Session lifecycle. One row per agent run: opened on the agent's first
attributed activity, closed after a period of inactivity. Session stat
columns (file_reads, file_writes, ...) are rolled up from the events
table when a session closes, then handed to baseline.update_from_session()."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from core.baseline import Baseline
from core.cross_agent import check_cross_agent_credential_access, check_cross_agent_file_conflict
from core.digest import generate_summary
from core.feature_flags import CORE_ONLY
from core.layer2a import score_session_2a
from core.layer2b import score_session_2b
from db.database import get_db

logger = logging.getLogger("vlaw")

SESSION_IDLE_TIMEOUT_SECONDS = 300  # close a session after 5 minutes of no activity
CLOSE_IDLE_SESSIONS_TIMEOUT_SECONDS = 8


class SessionManager:
    def __init__(self):
        # agent_id -> {"session_id": str, "last_activity": datetime}
        self._active: dict[int, dict] = {}
        # agent_id -> asyncio.Lock, created lazily per agent the first
        # time it's needed. Guards touch()'s own "decide whether to
        # split, then create and register the replacement" critical
        # section (see touch()) -- without it, several touch() calls
        # arriving concurrently for the same stale agent would all see
        # no active session (each awaits its own INSERT before any of
        # them gets to register the new one in self._active) and each
        # create its own duplicate replacement session. The lock makes
        # that sequence atomic from every other touch() call's point of
        # view; it does NOT guard the stale session's own close (see
        # touch()'s docstring for why that happens outside the lock).
        self._locks: dict[int, asyncio.Lock] = {}
        # Used only by touch()'s gap-split (see below) to score the
        # session it closes there. close_idle_sessions/recover_orphaned_
        # sessions still take their own baseline argument from the caller
        # (main.py) -- unchanged. Baseline itself holds no state of its
        # own beyond its Alerter's short in-memory dedup window (all real
        # state lives in the DB's baseline table), so a second instance
        # here is functionally interchangeable with the caller's.
        self._baseline = Baseline()

    def _lock_for(self, agent_id: int) -> asyncio.Lock:
        lock = self._locks.get(agent_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[agent_id] = lock
        return lock

    async def touch(self, agent_id: int, resumed: bool = False) -> str:
        """Record activity for an agent, opening a new session if none is
        active. Returns the current session_id for this agent.

        resumed=True marks a session opened for a process ProcessWatcher
        is only just discovering, not one that actually just started --
        see watchers/process_watcher.py's first-poll-after-restart flag.
        Its started_at is the moment Vigil (re)started watching, not the
        agent's real start time, so callers that build baselines/history
        from closed sessions (core/layer2b.py, core/baseline.py) exclude
        resumed=1 rows rather than treating this timestamp as real.
        Ignored once a session is already active for this agent (the
        existing-session return path below) -- a resumed session that
        later sees a genuine new spawn keeps its original resumed flag,
        it doesn't get overwritten or split into a second session.

        Gap split: if the agent already has an active session but the
        gap since its last activity already exceeds the idle timeout,
        that session was never actually closed on time -- self._active
        is in-memory and survives a sleep (the process is suspended, not
        restarted), so close_idle_sessions' own scheduled check never got
        a chance to fire on the stale gap before this very call would
        have refreshed last_activity and erased it (see the resumed-
        session investigation: a 3-day session spanning several sleeps).
        Closes the stale session through the same pipeline
        close_idle_sessions uses, backdated to when it actually went
        quiet, then opens a genuinely new one -- never resumed, this is
        a real continuation of activity, not a restart rediscovery.

        Concurrency: deciding to split and registering the replacement
        session happens under this agent's lock (see _lock_for), so N
        concurrent touch() calls arriving on the same stale agent
        produce exactly one replacement session -- whichever call
        acquires the lock first does the pop-and-create; every other
        call then finds that brand new session already registered and
        just returns it, the same as a normal touch within the timeout.
        Closing the stale session happens AFTER releasing the lock, so
        a slow or failing close (logged, never raised past here except
        CancelledError) never makes a concurrent touch() wait for it --
        only this specific call's own return is delayed by it."""
        db = await get_db()
        now = datetime.now(timezone.utc)

        stale = None
        async with self._lock_for(agent_id):
            active = self._active.get(agent_id)
            if active is not None:
                gap_seconds = (now - active["last_activity"]).total_seconds()
                if gap_seconds <= SESSION_IDLE_TIMEOUT_SECONDS:
                    active["last_activity"] = now
                    return active["session_id"]

                stale = self._active.pop(agent_id)
                resumed = False  # a gap split is a real continuation, never a restart rediscovery

            session_id = str(uuid.uuid4())
            from core.identity import get_operator_identity
            operator_username, operator_hostname = get_operator_identity()
            await db.execute(
                "INSERT INTO sessions (id, agent_id, started_at, operator_username, operator_hostname, resumed) "
                "VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?)",
                (session_id, agent_id, operator_username, operator_hostname, 1 if resumed else 0),
            )
            await db.execute(
                "UPDATE agents SET session_count = session_count + 1 WHERE id = ?",
                (agent_id,),
            )
            await db.commit()

            self._active[agent_id] = {"session_id": session_id, "last_activity": now}

        if stale is not None:
            try:
                await self._close_session(
                    db, self._baseline, stale["session_id"], agent_id,
                    ended_at=stale["last_activity"],
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "closing stale session %s on a long gap failed -- the new session %s is unaffected",
                    stale["session_id"], session_id,
                )

        return session_id

    async def close_idle_sessions(self, baseline) -> list[str]:
        """Called periodically by the scheduler. Closes any session whose
        agent has been inactive past the idle timeout, rolls up its stat
        columns from the events table, and feeds it to baseline. Returns
        the list of closed session_ids.

        Every DB call in this method and everything it calls into
        (_roll_up_session_stats, _write_summary, _score_layer2a/2b,
        _check_cross_agent, baseline.update_from_session) already goes
        through aiosqlite's `await db.execute`/`await db.commit` — there is
        no synchronous sqlite3 call anywhere in this call chain to move to
        a thread. What this loop can still do is take a while in real wall-
        clock time: it's a sequential run of several awaited DB round trips
        per idle agent (more than one agent going idle at once multiplies
        that), and _check_cross_agent in particular scans across the whole
        events table, not just this session. asyncio.timeout(8) bounds the
        whole method so a slow cycle cancels cleanly instead of running
        indefinitely; sessions already closed (committed) before the
        timeout fires stay closed — closed[] just stops growing.

        The idle_candidates snapshot below is taken once, then this loop
        awaits a full close per agent -- real time passes between
        agents, during which touch() can run for one of them (a new
        attributed event, or touch()'s own gap-split beating this loop
        to it). A blind self._active.pop(agent_id) here would then
        either raise KeyError (touch()'s gap-split already popped and
        replaced it) or, worse, pop and close the *new* session touch()
        just opened. Guarded instead: re-check the current entry right
        before popping, and only pop if it's still there, still the same
        session this snapshot saw, and still actually past the timeout
        (not refreshed by a normal touch() in the meantime). No lock
        needed here -- the lookup-compare-pop sequence has no await in
        the middle, so nothing else can observe or mutate self._active
        between the check and the pop; whichever of this loop or
        touch()'s own lock-guarded section gets there first simply wins,
        and the other correctly finds its target already gone or
        changed."""
        closed: list[str] = []
        try:
            async with asyncio.timeout(CLOSE_IDLE_SESSIONS_TIMEOUT_SECONDS):
                db = await get_db()
                now = datetime.now(timezone.utc)

                idle_candidates = [
                    (agent_id, info["session_id"])
                    for agent_id, info in self._active.items()
                    if (now - info["last_activity"]).total_seconds() >= SESSION_IDLE_TIMEOUT_SECONDS
                ]

                for agent_id, candidate_session_id in idle_candidates:
                    current = self._active.get(agent_id)
                    if current is None:
                        continue  # already closed/replaced elsewhere (e.g. touch()'s gap-split)
                    if current["session_id"] != candidate_session_id:
                        continue  # a different (newer) session is active now
                    recheck_gap = (datetime.now(timezone.utc) - current["last_activity"]).total_seconds()
                    if recheck_gap < SESSION_IDLE_TIMEOUT_SECONDS:
                        continue  # touched again since the snapshot was taken
                    self._active.pop(agent_id)
                    await self._close_session(db, baseline, candidate_session_id, agent_id)
                    closed.append(candidate_session_id)
        except TimeoutError:
            logger.warning(
                "SessionManager.close_idle_sessions timed out after %ds -- %d session(s) closed before timeout",
                CLOSE_IDLE_SESSIONS_TIMEOUT_SECONDS, len(closed),
            )

        return closed

    async def _close_session(
        self, db, baseline, session_id: str, agent_id: int, ended_at: datetime | None = None,
    ) -> None:
        """Shared close body for a single session: roll up its stat
        columns, set ended_at, fold it into baseline, score Layer 2a/2b,
        check cross-agent correlation, refresh the alert count, and write
        the summary -- the exact pipeline close_idle_sessions ran per
        session before this was factored out, now also used by touch()'s
        gap split (see there).

        ended_at=None uses CURRENT_TIMESTAMP (closing because the session
        is idle right now). An explicit datetime backdates ended_at to
        that moment instead, for a session closed well after the fact."""
        await self._roll_up_session_stats(db, session_id, agent_id)
        if ended_at is None:
            await db.execute("UPDATE sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?", (session_id,))
        else:
            await db.execute(
                "UPDATE sessions SET ended_at = ? WHERE id = ?",
                (ended_at.strftime("%Y-%m-%d %H:%M:%S"), session_id),
            )
        await db.commit()

        try:
            await baseline.update_from_session(session_id)
        except Exception as e:
            print(f"baseline update failed for session {session_id}: {e}")

        await self._score_layer2a(db, session_id, agent_id)
        await self._score_layer2b(db, session_id, agent_id)
        await self._check_cross_agent(db)
        # Alert-firing scoring above can add alerts that
        # _roll_up_session_stats' earlier count (taken before scoring
        # ran) couldn't see yet -- recount before writing the summary so
        # it reflects what actually got fired.
        await self._refresh_alert_count(db, session_id, agent_id)
        await self._write_summary(db, session_id, agent_id)

    async def _roll_up_session_stats(self, db, session_id: str, agent_id: int) -> None:
        cur = await db.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN event_type = 'file_read' THEN file_count ELSE 0 END), 0) as file_reads,
                COALESCE(SUM(CASE WHEN event_type = 'file_write' THEN file_count ELSE 0 END), 0) as file_writes,
                COALESCE(SUM(CASE WHEN event_type = 'net_connect' THEN data_volume_bytes ELSE 0 END), 0) as net_egress_bytes,
                COALESCE(SUM(CASE WHEN event_type = 'proc_spawn' THEN 1 ELSE 0 END), 0) as proc_spawns,
                COALESCE(SUM(CASE WHEN event_type = 'cred_access' THEN 1 ELSE 0 END), 0) as cred_accesses,
                COALESCE(SUM(CASE WHEN event_type = 'mcp_connect' THEN 1 ELSE 0 END), 0) as mcp_connects
            FROM events
            WHERE session_id = ? AND agent_id = ?
            """,
            (session_id, agent_id),
        )
        stats = await cur.fetchone()

        cur = await db.execute(
            """
            SELECT COUNT(*) c FROM alerts
            WHERE agent_id = ? AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?))
            """,
            (agent_id, session_id, session_id),
        )
        alert_count = (await cur.fetchone())["c"]

        await db.execute(
            """
            UPDATE sessions SET
                file_reads = ?, file_writes = ?, net_egress_bytes = ?,
                proc_spawns = ?, cred_accesses = ?, mcp_connects = ?, alert_count = ?
            WHERE id = ?
            """,
            (
                stats["file_reads"], stats["file_writes"], stats["net_egress_bytes"],
                stats["proc_spawns"], stats["cred_accesses"], stats["mcp_connects"],
                alert_count, session_id,
            ),
        )

    async def _refresh_alert_count(self, db, session_id: str, agent_id: int) -> None:
        """Recounts alerts for this session using the same WHERE clause as
        _roll_up_session_stats, and persists it -- called after Layer 2a/2b/
        cross-agent scoring has had a chance to fire alerts that the earlier
        roll-up (taken before scoring ran) couldn't have counted yet."""
        cur = await db.execute(
            """
            SELECT COUNT(*) c FROM alerts
            WHERE agent_id = ? AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?))
            """,
            (agent_id, session_id, session_id),
        )
        alert_count = (await cur.fetchone())["c"]

        await db.execute(
            "UPDATE sessions SET alert_count = ? WHERE id = ?",
            (alert_count, session_id),
        )
        await db.commit()

    async def _write_summary(self, db, session_id: str, agent_id: int) -> None:
        cur = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = await cur.fetchone()

        cur = await db.execute("SELECT name FROM agents WHERE id = ?", (agent_id,))
        agent = await cur.fetchone()
        agent_name = agent["name"] if agent else "unknown agent"

        summary = generate_summary(agent_name, dict(session))
        await db.execute("UPDATE sessions SET summary = ? WHERE id = ?", (summary, session_id))
        await db.commit()

    async def _score_layer2a(self, db, session_id: str, agent_id: int) -> None:
        """Layer 2a: embedded-prior anomaly checks. Session close must
        never fail due to scoring, so any error here is swallowed."""
        if CORE_ONLY:
            return
        try:
            cur = await db.execute("SELECT started_at FROM sessions WHERE id = ?", (session_id,))
            session = await cur.fetchone()

            cur = await db.execute("SELECT name FROM agents WHERE id = ?", (agent_id,))
            agent = await cur.fetchone()
            agent_name = agent["name"] if agent else "unknown agent"

            await score_session_2a(session_id, agent_id, agent_name, session["started_at"], db)
        except Exception as e:
            print(f"Layer2a scoring failed for session {session_id}: {e}")

    async def _score_layer2b(self, db, session_id: str, agent_id: int) -> None:
        """Layer 2b: rolling-window MAD anomaly checks. Session close
        must never fail due to scoring, so any error here is swallowed."""
        if CORE_ONLY:
            return
        try:
            cur = await db.execute("SELECT name FROM agents WHERE id = ?", (agent_id,))
            agent = await cur.fetchone()
            agent_name = agent["name"] if agent else "unknown agent"

            await score_session_2b(session_id, agent_id, agent_name, db)
        except Exception as e:
            print(f"Layer2b scoring failed: {e}")

    async def _check_cross_agent(self, db) -> None:
        """Cross-agent correlation: same-file conflicts and credential
        access aggregated across all agents, not scoped to the session
        that just closed — these checks compare activity across the whole
        unified event store. Session close must never fail due to scoring,
        so any error here is swallowed, exactly like Layer 2a/2b above."""
        try:
            await check_cross_agent_file_conflict(db)
            await check_cross_agent_credential_access(db)
        except Exception as e:
            print(f"Cross-agent correlation check failed: {e}")

    async def recover_orphaned_sessions(self, baseline) -> int:
        """Startup-time recovery: a session whose process died before
        close_idle_sessions ever got to it is left with ended_at NULL
        forever (self._active is in-memory only, so it doesn't survive a
        restart either) -- never rolled up, never scored, never
        summarized. Call once at startup to close out every such session
        from the previous run, running the same roll-up/scoring/summary
        pipeline close_idle_sessions uses (baseline update, Layer 2a/2b,
        alert-count refresh) so a recovered session isn't a second-class
        citizen next to one that closed normally. _check_cross_agent runs
        once after the loop, not per session -- it already scans the whole
        events table, not just the session that just closed.

        Each session is recovered independently: one bad row (a query
        that fails, malformed data, whatever) is logged and skipped rather
        than aborting the rest -- it's simply left with ended_at still
        NULL and picked up again on the next startup. Returns the number
        actually recovered, not the number of candidate rows."""
        db = await get_db()
        cur = await db.execute("SELECT id, agent_id FROM sessions WHERE ended_at IS NULL")
        rows = await cur.fetchall()

        recovered = 0
        for row in rows:
            session_id = row["id"]
            agent_id = row["agent_id"]
            try:
                await self._roll_up_session_stats(db, session_id, agent_id)
                await db.execute(
                    """
                    UPDATE sessions
                    SET ended_at = COALESCE((SELECT MAX(created_at) FROM events WHERE session_id = ?), started_at)
                    WHERE id = ?
                    """,
                    (session_id, session_id),
                )
                await db.commit()

                try:
                    await baseline.update_from_session(session_id)
                except Exception as e:
                    print(f"baseline update failed for session {session_id}: {e}")

                await self._score_layer2a(db, session_id, agent_id)
                await self._score_layer2b(db, session_id, agent_id)
                await self._refresh_alert_count(db, session_id, agent_id)
                await self._write_summary(db, session_id, agent_id)
                recovered += 1
            except Exception:
                logger.exception("session recovery failed for session_id=%s -- left for next startup", session_id)

        await self._check_cross_agent(db)

        return recovered
