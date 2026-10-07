"""Tracks when Vigil itself was actually running, independent of what any
watcher observed. Two tables (see db/schema.sql): vigil_runs (one row per
backend process lifetime, with a last_seen_at heartbeat advanced every
~30s) and monitoring_gaps (append-only, one row per detected gap -- either
a pause inside a single run, long enough to look like sleep/suspend
rather than a slow tick, or the whole span between one run ending and the
next one starting).

The heartbeat rides on process_watcher.poll()'s existing 30s scheduler
job rather than a new one of its own -- see the comment at that job's
registration in main.py and at record_coverage_tick() below. This means
coverage tracking depends on that job continuing to run; if it's ever
disabled the way network_watcher/mcp_watcher already have been, coverage
silently stops advancing too.

Never raises. A DB write failure here must never take down the backend or
the watcher tick it rides on -- every public function is self-contained,
matching core/evidence_chain.py's seal_new_events() pattern. A gap that
fails to insert is kept in memory and retried on every subsequent tick
until it succeeds, so a transient DB problem can delay a gap being
recorded but never silently drop it -- except across a hard crash, since
nothing survives in memory through one; that's an accepted limit, not
something this module can fix without a separate durable fallback store.
"""

import logging
import uuid
from datetime import datetime, timezone

from db.database import get_db

logger = logging.getLogger("vlaw")

# 3 missed 30s ticks -- long enough that one slow tick (a subprocess scan
# under load, which this machine has measured taking 40s+) can't trip a
# false gap on its own, short enough to still catch a real sleep/suspend
# promptly. Deliberately separate from export.py's short-gap display
# threshold below -- this one guards against false positives from normal
# tick jitter, that one is a presentation decision about what's worth
# listing individually in a report.
GAP_DETECTION_THRESHOLD_SECONDS = 90

REASON_NOT_RUNNING = "Vigil was not running"
REASON_SLEEP = "monitoring paused (computer likely asleep, or Vigil was suspended)"

_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_TS_FORMAT)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


class CoverageTracker:
    """Instance state for one backend process's coverage tracking. A
    module-level singleton (_tracker below) is what main.py and
    process_watcher.py actually use, but the class itself takes no
    dependency on that singleton -- tests construct their own instances
    so they never share state with each other or with the real one."""

    def __init__(self):
        self.run_id: str | None = None
        self.last_seen_at: datetime | None = None
        # Gaps that were detected but failed to insert, kept here until a
        # later tick's flush succeeds. Order doesn't matter for
        # correctness, only that nothing in this list is ever dropped
        # without either being written or the process dying.
        self.pending_gaps: list[dict] = []

    async def _insert_gap(self, db, gap: dict) -> bool:
        """Returns True on success. Never raises -- callers decide what
        to do with a failed insert (this class always queues it)."""
        try:
            await db.execute(
                "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES (?, ?, ?, ?)",
                (gap["run_id"], _fmt(gap["gap_start"]), _fmt(gap["gap_end"]), gap["reason"]),
            )
            await db.commit()
            return True
        except Exception:
            logger.exception("monitoring coverage: failed to insert gap, will retry next tick: %s", gap)
            return False

    async def _flush_pending_gaps(self, db) -> None:
        if not self.pending_gaps:
            return
        still_pending = []
        for gap in self.pending_gaps:
            if not await self._insert_gap(db, gap):
                still_pending.append(gap)
        self.pending_gaps = still_pending

    async def start_run(self) -> str | None:
        """Call once at startup, after init_db(). Opens a new run row and,
        if a previous run exists, records the gap between that run's last
        heartbeat and this one's start as "Vigil was not running" --
        however short, per design (folding short ones is a display-time
        decision, not a storage-time one). Returns the new run_id, or
        None if even starting the run failed (coverage tracking is simply
        unavailable for this process's lifetime; nothing else is allowed
        to fail because of that)."""
        try:
            db = await get_db()
            now = datetime.now(timezone.utc)
            run_id = str(uuid.uuid4())

            cur = await db.execute("SELECT last_seen_at FROM vigil_runs ORDER BY id DESC LIMIT 1")
            previous = await cur.fetchone()

            if previous is not None:
                previous_last_seen = _parse(previous["last_seen_at"])
                if now > previous_last_seen:
                    gap = {
                        "run_id": run_id, "gap_start": previous_last_seen, "gap_end": now,
                        "reason": REASON_NOT_RUNNING,
                    }
                    if not await self._insert_gap(db, gap):
                        self.pending_gaps.append(gap)
                else:
                    # now <= previous_last_seen: the clock moved backwards
                    # across the restart (impossible under correct clocks,
                    # since the previous run had to stop before this one's
                    # single-instance lock could be acquired). No gap --
                    # a gap here would have a negative or zero duration.
                    logger.warning(
                        "monitoring coverage: system clock appears to have moved backwards across "
                        "restart (previous run's last_seen_at=%s, this run's started_at=%s) -- "
                        "no 'Vigil was not running' gap recorded for this restart",
                        previous_last_seen, now,
                    )

            await db.execute(
                "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
                (run_id, _fmt(now), _fmt(now)),
            )
            await db.commit()

            self.run_id = run_id
            self.last_seen_at = now
            logger.info("monitoring coverage: run %s started", run_id)
            return run_id
        except Exception:
            logger.exception("monitoring coverage: failed to start run -- coverage tracking disabled this run")
            return None

    async def record_tick(self) -> None:
        """Call on process_watcher.poll()'s existing 30s schedule -- see
        the comment there. Always attempts to flush any pending gaps
        first, regardless of whether this run itself is trackable right
        now, since a pending gap is independent data waiting to be
        written, not conditional on this tick's own run state."""
        try:
            db = await get_db()
            await self._flush_pending_gaps(db)
        except Exception:
            logger.exception("monitoring coverage: tick failed during pending-gap flush")

        if self.run_id is None:
            return

        try:
            now = datetime.now(timezone.utc)

            if self.last_seen_at is not None and now <= self.last_seen_at:
                # Clock moved backwards since the last tick. Skip this
                # tick's gap check entirely rather than compute a
                # negative or zero-duration gap, and don't regress the
                # stored last_seen_at -- the next tick, once the clock
                # has caught back up past it, resumes normal detection
                # against this same unregressed value.
                logger.warning(
                    "monitoring coverage: system clock appears to have moved backwards "
                    "(last_seen_at=%s, now=%s) -- skipping this tick's gap check",
                    self.last_seen_at, now,
                )
                return

            if (
                self.last_seen_at is not None
                and (now - self.last_seen_at).total_seconds() > GAP_DETECTION_THRESHOLD_SECONDS
            ):
                gap = {
                    "run_id": self.run_id, "gap_start": self.last_seen_at, "gap_end": now,
                    "reason": REASON_SLEEP,
                }
                db = await get_db()
                if not await self._insert_gap(db, gap):
                    self.pending_gaps.append(gap)

            self.last_seen_at = now

            try:
                db = await get_db()
                await db.execute(
                    "UPDATE vigil_runs SET last_seen_at = ? WHERE run_id = ?",
                    (_fmt(now), self.run_id),
                )
                await db.commit()
            except Exception:
                logger.exception("monitoring coverage: failed to update last_seen_at for run %s", self.run_id)
        except Exception:
            logger.exception("monitoring coverage: tick failed")

    async def mark_clean_shutdown(self) -> None:
        """Call from the lifespan teardown block. Purely informational --
        never read by the gap-detection logic above, since the tray
        force-kills the backend on an ordinary quit, making this 0 even
        for a perfectly normal shutdown. Kept only in case it's useful
        for a future diagnostic display."""
        if self.run_id is None:
            return
        try:
            db = await get_db()
            await db.execute("UPDATE vigil_runs SET clean_shutdown = 1 WHERE run_id = ?", (self.run_id,))
            await db.commit()
        except Exception:
            logger.exception("monitoring coverage: failed to mark clean shutdown for run %s", self.run_id)


_tracker = CoverageTracker()


async def start_run() -> str | None:
    return await _tracker.start_run()


async def record_coverage_tick() -> None:
    # Rides on process_watcher.poll()'s existing 30s job rather than a
    # scheduler job of its own -- see the registration comment in
    # main.py. If that job is ever disabled, coverage silently stops
    # advancing with it.
    await _tracker.record_tick()


async def mark_clean_shutdown() -> None:
    await _tracker.mark_clean_shutdown()
