"""Session lifecycle. One row per agent run: opened on the agent's first
attributed activity, closed after a period of inactivity. Session stat
columns (file_reads, file_writes, ...) are rolled up from the events
table when a session closes, then handed to baseline.update_from_session()."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

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

    async def touch(self, agent_id: int) -> str:
        """Record activity for an agent, opening a new session if none is
        active. Returns the current session_id for this agent."""
        db = await get_db()
        now = datetime.now(timezone.utc)

        active = self._active.get(agent_id)
        if active is not None:
            active["last_activity"] = now
            return active["session_id"]

        session_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (session_id, agent_id),
        )
        await db.execute(
            "UPDATE agents SET session_count = session_count + 1 WHERE id = ?",
            (agent_id,),
        )
        await db.commit()

        self._active[agent_id] = {"session_id": session_id, "last_activity": now}
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
        timeout fires stay closed — closed[] just stops growing."""
        closed: list[str] = []
        try:
            async with asyncio.timeout(CLOSE_IDLE_SESSIONS_TIMEOUT_SECONDS):
                db = await get_db()
                now = datetime.now(timezone.utc)

                idle_agent_ids = [
                    agent_id
                    for agent_id, info in self._active.items()
                    if (now - info["last_activity"]).total_seconds() >= SESSION_IDLE_TIMEOUT_SECONDS
                ]

                for agent_id in idle_agent_ids:
                    info = self._active.pop(agent_id)
                    session_id = info["session_id"]

                    await self._roll_up_session_stats(db, session_id, agent_id)
                    await db.execute(
                        "UPDATE sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (session_id,),
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
                    # _roll_up_session_stats' earlier count (taken before
                    # scoring ran) couldn't see yet -- recount before writing
                    # the summary so it reflects what actually got fired.
                    await self._refresh_alert_count(db, session_id, agent_id)
                    await self._write_summary(db, session_id, agent_id)
                    closed.append(session_id)
        except TimeoutError:
            logger.warning(
                "SessionManager.close_idle_sessions timed out after %ds -- %d session(s) closed before timeout",
                CLOSE_IDLE_SESSIONS_TIMEOUT_SECONDS, len(closed),
            )

        return closed

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
