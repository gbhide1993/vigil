"""Event aggregation engine. Raw OS events are too noisy to write directly
to the events table, so file and network events are buffered in time
windows and collapsed before being persisted. Credential-path file events
and process spawns bypass aggregation entirely and are written immediately.

All of Aggregator's own writes (flush_buffers, _write_credential_event) are
funneled through a single internal asyncio.Queue + writer coroutine (see
enqueue/start_writer/stop_writer below), so this class is the sole writer
for the events it owns. Other modules (watchers, Attributor, SessionManager,
Alerter) still call db.database.get_db() directly for their own writes —
their callers depend on synchronous read-your-own-write results (lastrowid,
agent_id, session_id) that a queued/deferred write can't provide without a
much larger refactor of those call chains."""

import asyncio
import logging
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from core.alerter import Alerter
from db.database import get_db

logger = logging.getLogger("vlaw")

FILE_WINDOW_SECONDS = 5
NET_WINDOW_SECONDS = 60
FILE_EVENT_BUFFER_MAX = 1000

CREDENTIAL_PATTERNS = [".env", ".ssh", ".aws", ".pem", ".key"]


def _is_credential_path(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in CREDENTIAL_PATTERNS)


def _crash_recovery_path() -> Path:
    """Fixed location regardless of frozen/script mode, per spec — not
    derived from main.py's BASE_DIR (which differs between the two)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return Path(base) / "V-LAW" / "crash_recovery.log"


def _format_created_at(timestamp) -> str:
    """Formats an epoch float into the same 'YYYY-MM-DD HH:MM:SS' (UTC)
    shape SQLite's own CURRENT_TIMESTAMP produces, so buffered/replayed
    rows sort and compare correctly against rows written the normal way.
    Falls back to now() for a missing/invalid timestamp rather than
    returning None — binding NULL to a DEFAULT-valued column stores NULL,
    it does not fall back to the column default."""
    if timestamp is not None:
        try:
            return datetime.fromtimestamp(float(timestamp), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Aggregator:
    def __init__(self):
        # (agent_id, dir) -> {"count": int, "window_start": float, "event_type": str, "paths": set}
        self._file_buffer: dict[tuple, dict] = {}
        # (agent_id, host) -> {"request_count": int, "bytes_out": int, "window_start": float}
        self._net_buffer: dict[tuple, dict] = {}
        self.alerter = Alerter()

        # Real-time (ETW / native-observer heuristic) file events, buffered
        # here instead of writing to SQLite per event -- see
        # buffer_file_event/flush_buffers. Distinct from _file_buffer above:
        # that one collapses many polling-tier events into one row per
        # (agent, directory) window; this one preserves each real-time
        # event as its own row, just batches the INSERTs.
        self.file_event_buffer: list[dict] = []
        self._buffer_lock = asyncio.Lock()

        self._write_queue: asyncio.Queue = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None

        # PRAGMA wal_checkpoint(PASSIVE) used to run on every flush_buffers
        # call (every 15s) -- passive checkpoints wait for readers to clear
        # rather than blocking them, but under sustained real-time file
        # activity a checkpoint was frequently landing mid-read and losing
        # the race to "database table is locked" anyway. Since flush_buffers
        # already durably drains both buffers into SQLite every cycle
        # regardless of whether a checkpoint runs, there's no correctness
        # reason to checkpoint that often -- only WAL file size. Throttling
        # to every 10th flush (~150s) cuts checkpoint frequency 10x while
        # still bounding WAL growth.
        self._flush_count = 0
        self._checkpoint_every = 10

    async def start_writer(self) -> None:
        """Single writer coroutine — the only place Aggregator's own
        queued writes actually touch the DB. Run as a background task
        (see main.py lifespan) for the life of the process."""
        while True:
            try:
                coro_factory, future = await asyncio.wait_for(
                    self._write_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            try:
                result = await coro_factory()
                if not future.done():
                    future.set_result(result)
            except Exception as e:
                logger.error("aggregator writer error: %s", e)
                # Root cause of the recurring "database table is locked"
                # errors this was meant to fix: a failed write (constraint
                # violation, bad param, ...) leaves the shared aiosqlite
                # connection sitting in an open, uncommitted transaction --
                # nothing here ever called commit() for it, and Python's
                # sqlite3 doesn't auto-rollback a failed statement. Every
                # later operation on this same connection (including the
                # periodic wal_checkpoint below) then hits "table is
                # locked" against that stuck transaction, permanently,
                # until the process restarts. Rolling back here is what
                # actually prevents one bad write from poisoning every
                # write after it for the rest of the process's life.
                try:
                    db = await get_db()
                    await db.rollback()
                except Exception:
                    logger.exception("aggregator writer: rollback after failed write also failed")
                if not future.done():
                    future.set_exception(e)
            finally:
                self._write_queue.task_done()

    async def enqueue(self, coro_factory):
        """coro_factory: zero-arg callable returning the write coroutine to
        run on the writer task. Returns a Future that resolves to whatever
        that coroutine returns, once the writer actually executes it."""
        future = asyncio.get_event_loop().create_future()
        await self._write_queue.put((coro_factory, future))
        return await future

    async def stop_writer(self) -> None:
        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass

    async def ingest_file_event(self, event: dict) -> None:
        """event: {agent_id, session_id, path, event_type,
        attribution_confidence?, pid?, event_source?}

        event_source != "poll" (i.e. "etw" or "realtime_heuristic") skips
        directory/time-bucket aggregation entirely and goes to the
        in-memory file_event_buffer instead (see buffer_file_event) —
        aggregation exists to collapse the old polling tier's redundant,
        delayed re-detection of the same changes into one row per window; a
        real-time event with its own exact-ish timestamp and (often) a real
        per-process pid is exactly the granularity this feature exists to
        preserve, so collapsing it back down into a shared directory bucket
        would throw away the one thing that makes it worth having. The
        polling tier (event_source == "poll", the default) keeps the
        original aggregated behaviour unchanged.

        Real-time events used to be written to SQLite individually, one
        INSERT+commit per event (see _write_realtime_file_event, kept below
        as the direct-write fallback for when buffering isn't available) —
        under high-frequency ETW activity that meant one commit per file
        event, which was producing WAL lock contention and, per testing,
        silent write failures. Buffering collapses that down to one
        executemany + one commit per flush_buffers cycle (every 15s)."""
        path = event["path"]
        confidence = event.get("attribution_confidence", "high")
        event_source = event.get("event_source", "poll")

        if _is_credential_path(path):
            await self._write_credential_event(event)
            return

        if event_source != "poll":
            await self.buffer_file_event({
                "agent_id": event["agent_id"],
                "session_id": event["session_id"],
                "event_type": event["event_type"],
                "path": path,
                "detail": {"attribution_confidence": confidence},
                "severity": "low",
                "pid": event.get("pid"),
                "event_source": event_source,
                "timestamp": event.get("timestamp", time.time()),
            })
            return

        directory = str(Path(path).parent)
        key = (event["agent_id"], directory)
        now = time.time()

        buf = self._file_buffer.get(key)
        if buf is None:
            self._file_buffer[key] = {
                "session_id": event["session_id"],
                "event_type": event["event_type"],
                "window_start": now,
                "count": 1,
                "paths": {path},
                "confidence": confidence,
            }
            return

        buf["count"] += 1
        buf["paths"].add(path)
        if event["event_type"] != buf["event_type"]:
            buf["event_type"] = "file_write"  # mixed read/write escalates to write
        if confidence == "low":
            buf["confidence"] = "low"  # any low-confidence event taints the window

    async def ingest_net_event(self, event: dict) -> None:
        """event: {agent_id, session_id, host, bytes_out}"""
        key = (event["agent_id"], event["host"])
        now = time.time()

        buf = self._net_buffer.get(key)
        if buf is None:
            self._net_buffer[key] = {
                "session_id": event["session_id"],
                "window_start": now,
                "request_count": 1,
                "bytes_out": event.get("bytes_out", 0),
            }
            return

        buf["request_count"] += 1
        buf["bytes_out"] += event.get("bytes_out", 0)

    async def buffer_file_event(self, event: dict) -> None:
        """Appends a real-time file event to the in-memory buffer instead
        of writing it to SQLite immediately — see flush_buffers, which
        drains this in one batched INSERT every 15s. This is the actual
        fix for the WAL contention: many small INSERT+commit pairs (one
        per file event) become one executemany + one commit per flush.

        event must contain: agent_id, session_id, event_type, path,
        detail, severity, pid, event_source, timestamp.

        Safe to call from any coroutine on the event loop; never call this
        directly from the ETW/watchdog background threads — dispatch onto
        the loop with asyncio.run_coroutine_threadsafe first (see
        etw_file_watcher.py/file_watcher.py, which already do this to
        reach VlawFileHandler in the first place)."""
        async with self._buffer_lock:
            if len(self.file_event_buffer) >= FILE_EVENT_BUFFER_MAX:
                dropped = self.file_event_buffer.pop(0)
                logger.warning(
                    "file_event_buffer full (%d events) -- dropping oldest buffered event "
                    "(path=%s) to make room",
                    FILE_EVENT_BUFFER_MAX, dropped.get("path"),
                )
            self.file_event_buffer.append(event)

        self._append_crash_recovery_line(event)

    def _append_crash_recovery_line(self, event: dict) -> None:
        """Best-effort durability for the in-memory buffer: if the process
        dies before the next flush, this line is how a buffered-but-not-
        yet-written event survives to be replayed on the next startup (see
        replay_crash_recovery_log). Never allowed to affect the caller —
        any failure here (disk full, permissions, ...) is logged and
        swallowed. Note: this provides at-least-once durability, not
        exactly-once — see flush_buffers' docstring for the narrow window
        where a crash can still lose an event appended in the same instant
        a flush clears the log."""
        try:
            path = _crash_recovery_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except Exception:
            logger.exception("crash recovery: failed to append event, continuing without it")

    def _clear_crash_recovery_log(self) -> None:
        try:
            path = _crash_recovery_path()
            if path.exists():
                path.unlink()
        except Exception:
            logger.exception("crash recovery: failed to clear log, continuing")

    async def replay_crash_recovery_log(self) -> int:
        """Startup-time recovery: if crash_recovery.log exists (the process
        was killed before a previous buffer flush completed — see
        _append_crash_recovery_line), replay every line straight into
        SQLite, then delete the file. Call once at startup, after init_db()
        but before start_writer() (see main.py) — uses get_db() directly
        rather than enqueue() since the writer task isn't running yet.

        Best-effort: any failure here is logged and swallowed, never
        raised, so a corrupt/unreadable recovery file can never block
        startup — worst case it's left on disk and retried next startup.
        Returns the number of events successfully replayed."""
        path = _crash_recovery_path()
        try:
            if not path.exists():
                return 0
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            logger.exception("crash recovery: failed to read %s, skipping replay", path)
            return 0

        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                logger.warning("crash recovery: skipping unparseable line in %s", path)

        if not events:
            try:
                path.unlink()
            except Exception:
                logger.exception("crash recovery: failed to delete empty/unparseable %s", path)
            return 0

        try:
            db = await get_db()
            await db.executemany(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, severity, pid, event_source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e.get("agent_id"), e.get("session_id"), e.get("event_type"), e.get("path"),
                        json.dumps(e.get("detail") or {}), e.get("severity", "low"),
                        e.get("pid"), e.get("event_source"),
                        _format_created_at(e.get("timestamp")),
                    )
                    for e in events
                ],
            )
            await db.commit()
        except Exception:
            logger.exception(
                "crash recovery: failed to replay %d events, leaving %s intact for next startup",
                len(events), path,
            )
            return 0

        try:
            path.unlink()
        except Exception:
            logger.exception("crash recovery: replay succeeded but failed to delete %s", path)

        logger.info("crash recovery: replayed %d buffered file events from %s", len(events), path)
        return len(events)

    async def flush_buffers(self) -> None:
        """Called periodically by the scheduler. Flushes windows that have
        elapsed and writes a single aggregated event per (agent, scope).
        Writes are routed through enqueue() so this Aggregator instance's
        single writer coroutine is the only thing executing them."""
        now = time.time()

        expired_file_keys = [
            k for k, v in self._file_buffer.items()
            if now - v["window_start"] >= FILE_WINDOW_SECONDS
        ]
        for key in expired_file_keys:
            agent_id, directory = key
            buf = self._file_buffer.pop(key)

            async def _write_file_event(agent_id=agent_id, directory=directory, buf=buf):
                db = await get_db()
                cur = await db.execute(
                    """
                    INSERT INTO events
                        (agent_id, session_id, event_type, path, detail, file_count, severity, event_source)
                    VALUES (?, ?, ?, ?, ?, ?, 'low', 'poll')
                    """,
                    (
                        agent_id,
                        buf["session_id"],
                        buf["event_type"],
                        directory,
                        json.dumps({
                            "paths": sorted(buf["paths"])[:50],
                            "attribution_confidence": buf["confidence"],
                        }),
                        buf["count"],
                    ),
                )
                await db.commit()
                return cur.lastrowid

            event_id = await self.enqueue(_write_file_event)
            await self.alerter.check_out_of_scope_access(
                agent_id, directory, event_id=event_id, session_id=buf["session_id"],
            )

        expired_net_keys = [
            k for k, v in self._net_buffer.items()
            if now - v["window_start"] >= NET_WINDOW_SECONDS
        ]
        for key in expired_net_keys:
            agent_id, host = key
            buf = self._net_buffer.pop(key)

            async def _write_net_event(agent_id=agent_id, host=host, buf=buf):
                db = await get_db()
                await db.execute(
                    """
                    INSERT INTO events
                        (agent_id, session_id, event_type, path, detail, data_volume_bytes, severity)
                    VALUES (?, ?, 'net_connect', ?, ?, ?, 'low')
                    """,
                    (
                        agent_id,
                        buf["session_id"],
                        host,
                        json.dumps({"request_count": buf["request_count"]}),
                        buf["bytes_out"],
                    ),
                )
                await db.commit()

            await self.enqueue(_write_net_event)

        await self._flush_file_event_buffer()

        self._flush_count += 1
        if self._flush_count % self._checkpoint_every == 0:
            async def _checkpoint():
                db = await get_db()
                await db.execute("PRAGMA wal_checkpoint(PASSIVE)")

            await self.enqueue(_checkpoint)

    async def _flush_file_event_buffer(self) -> None:
        """Drains file_event_buffer in one batched INSERT + one commit,
        instead of the one-INSERT-plus-commit-per-event this replaced (see
        ingest_file_event's docstring). Only removes the events it actually
        wrote: it snapshots the buffer under the lock, writes that snapshot
        outside the lock (so buffer_file_event can keep appending new
        events concurrently without blocking on the DB write), then removes
        exactly that prefix — never a blind .clear(), which would silently
        drop anything appended while the write was in flight.

        On failure, the buffer (and the crash-recovery log) are left
        exactly as they were — nothing is lost, it's just retried on the
        next flush_buffers cycle."""
        async with self._buffer_lock:
            if not self.file_event_buffer:
                return
            batch = list(self.file_event_buffer)

        async def _write_batch(batch=batch):
            db = await get_db()
            await db.executemany(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, severity, pid, event_source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e["agent_id"], e["session_id"], e["event_type"], e["path"],
                        json.dumps(e.get("detail") or {}), e.get("severity", "low"),
                        e.get("pid"), e.get("event_source"),
                        _format_created_at(e.get("timestamp")),
                    )
                    for e in batch
                ],
            )
            await db.commit()

        try:
            await self.enqueue(_write_batch)
        except Exception as e:
            logger.error(
                "file_event_buffer flush failed, keeping %d buffered events for retry: %s",
                len(batch), e,
            )
            return

        async with self._buffer_lock:
            del self.file_event_buffer[: len(batch)]

        # Per spec: unconditional on any successful flush. Narrow race,
        # disclosed in _append_crash_recovery_line's docstring: an event
        # appended to the log in the instant between the snapshot above and
        # this delete loses its recovery-log line despite still being in
        # memory (behind `batch` in file_event_buffer) -- it's still safe
        # today (the next flush will write it from memory as normal), only
        # its crash-durability is briefly uncovered. Acceptable for a
        # best-effort recovery mechanism; not acceptable if this were the
        # only copy of the data.
        self._clear_crash_recovery_log()

    async def _write_credential_event(self, event: dict) -> None:
        """Credential paths are never aggregated — always individual,
        immediately processed events. Routed through enqueue() like
        flush_buffers() above."""
        pid = event.get("pid")
        event_source = event.get("event_source", "poll")

        async def _write():
            db = await get_db()
            cur = await db.execute(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, file_count, severity, pid, event_source)
                VALUES (?, ?, 'cred_access', ?, ?, 1, 'high', ?, ?)
                """,
                (
                    event["agent_id"],
                    event["session_id"],
                    event["path"],
                    json.dumps({
                        "event_type": event["event_type"],
                        "attribution_confidence": event.get("attribution_confidence", "high"),
                    }),
                    pid,
                    event_source,
                ),
            )
            await db.commit()
            return cur.lastrowid

        event_id = await self.enqueue(_write)
        await self.alerter.check_credential_access(
            event["agent_id"], event["path"], event_id=event_id, session_id=event["session_id"],
        )

    async def _write_realtime_file_event(self, event: dict) -> None:
        """Direct-write fallback for a real-time file event, kept for
        callers that can't go through the file_event_buffer (see
        VlawFileHandler.handle_file_event's `self.aggregator is None`
        branch in file_watcher.py) — ingest_file_event's normal path uses
        buffer_file_event instead (see its docstring for why: this
        one-INSERT-plus-commit-per-event pattern is what caused the WAL
        lock contention buffering exists to fix). Runs the same
        out-of-scope-directory check flush_buffers's aggregated path runs
        for the polling tier, since that's the only place it would
        otherwise happen — routed through enqueue() like the two paths
        above."""
        agent_id = event["agent_id"]
        path = event["path"]

        async def _write():
            db = await get_db()
            cur = await db.execute(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, file_count, severity, pid, event_source)
                VALUES (?, ?, ?, ?, ?, 1, 'low', ?, ?)
                """,
                (
                    agent_id,
                    event["session_id"],
                    event["event_type"],
                    path,
                    json.dumps({
                        "attribution_confidence": event.get("attribution_confidence", "high"),
                    }),
                    event["pid"],
                    event["event_source"],
                ),
            )
            await db.commit()
            return cur.lastrowid

        event_id = await self.enqueue(_write)
        await self.alerter.check_out_of_scope_access(
            agent_id, path, event_id=event_id, session_id=event["session_id"],
        )
