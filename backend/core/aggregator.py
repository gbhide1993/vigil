"""Event aggregation engine. Raw OS events are too noisy to write directly
to the events table, so file and network events are buffered in time
windows and collapsed before being persisted. Credential-path file events
and process spawns bypass aggregation entirely and are written immediately.

All of Aggregator's own writes (flush_buffers, _write_credential_event) are
funneled through a single internal asyncio.Queue + writer coroutine (see
enqueue/start_writer/stop_writer below). ProcessWatcher's batched proc_spawn
INSERT (its one write big enough to meaningfully contend with Aggregator's
own writes under SQLite WAL's single-writer-at-a-time rule) is also routed
through enqueue() as of the fix below -- see ProcessWatcher._poll_write_body
-- so this queue is now the sole path for every write large/frequent enough
to matter for contention. Other modules (Attributor, SessionManager, RedLines,
Alerter, and ProcessWatcher's smaller per-PID calls into those) still call
db.database.get_db() directly for their own writes — their callers depend on
synchronous read-your-own-write results (lastrowid, agent_id, session_id)
that a queued/deferred write can't provide without a much larger refactor of
those call chains, and those writes are individually small enough that they
were not the source of the contention this fix addresses."""

import asyncio
import logging
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from core.alerter import Alerter
from core.evidence_store import evidence_store
from db.database import get_db, get_read_db, replace_db, DB_PATH

logger = logging.getLogger("vlaw")

FILE_WINDOW_SECONDS = 5
NET_WINDOW_SECONDS = 60
FILE_EVENT_BUFFER_MAX = 1000

# Write watchdog (see start_writer): how long a single queued write is
# allowed to run before we try conn.interrupt() on it, and how much
# longer after that before we give up and replace the connection
# outright. Comfortably above normal write_batch latency (observed
# 0.3-7s in practice) so this never fires on ordinary slow writes.
WRITE_INTERRUPT_AFTER_SECONDS = 12
WRITE_REPLACE_GRACE_SECONDS = 8
# More than this many replacements in one process lifetime means the
# wedging is recurring, not transient -- see _replace_wedged_connection.
MAX_CONNECTION_REPLACEMENTS = 2

CREDENTIAL_PATTERNS = [".env", ".ssh", ".aws", ".pem", ".key"]


class ConnectionWedgedError(Exception):
    """Raised on a queued write's future when the shared DB connection had
    to be replaced out from under it -- see start_writer/_run_write_with_
    watchdog. The write's actual outcome (did it commit before the
    connection wedged?) is unknowable; callers should treat this exactly
    like any other failed write."""


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
        # Kept open across calls (see _append_crash_recovery_line) rather
        # than opened and closed per event -- that per-event open+close was
        # running synchronously on the event loop's own thread and, under
        # sustained real-time file-event volume, was the confirmed cause of
        # a sustained-CPU/scheduler-lag pattern (py-spy caught the event
        # loop thread inside this exact call on every sample). Reset to
        # None whenever the file needs to be reopened fresh (first use, or
        # after _clear_crash_recovery_log closes and unlinks it).
        self._crash_recovery_file = None
        self._crash_recovery_dir_ensured = False

        self._write_queue: asyncio.Queue = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None
        # See _replace_wedged_connection -- counts how many times the
        # shared connection has been abandoned-and-replaced this process
        # lifetime, to escalate past MAX_CONNECTION_REPLACEMENTS instead
        # of silently replacing forever.
        self._connection_replace_count = 0

        # PRAGMA wal_checkpoint(PASSIVE) runs periodically (every 10th
        # flush, ~150s) on its own dedicated connection -- see
        # _checkpoint() -- never through enqueue() / the shared writer
        # queue, so a slow checkpoint can't block Aggregator/
        # ProcessWatcher/VlawFileHandler writes that share that queue.
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
                await self._run_write_with_watchdog(coro_factory, future)
            except Exception:
                # Final backstop. _run_write_with_watchdog and everything it
                # calls (_try_interrupt, _replace_wedged_connection,
                # _handle_write_exception) are expected to handle their own
                # failures internally and never raise past this point -- but
                # confirmed live: _replace_wedged_connection's replace_db()
                # call can itself raise "database is locked" (the abandoned
                # connection's thread can still be holding the WAL lock),
                # and before this fix that exception had nowhere caught it,
                # silently killing this whole loop. Every future enqueue()
                # call then hangs forever while the rest of the process
                # (including /health) keeps looking alive -- worse than a
                # clean crash. Exit deliberately instead so the existing
                # supervisor (tray app / VS Code extension) restarts the
                # backend fresh rather than leaving a zombie writer.
                logger.critical(
                    "aggregator writer: unhandled exception escaped "
                    "_run_write_with_watchdog -- exiting so the supervisor restarts "
                    "the backend instead of leaving a zombie writer that hangs every "
                    "future enqueue() call",
                    exc_info=True,
                )
                if not future.done():
                    future.set_exception(
                        ConnectionWedgedError("aggregator writer crashed handling this write")
                    )
                os._exit(1)
            finally:
                self._write_queue.task_done()

    async def _run_write_with_watchdog(self, coro_factory, future) -> None:
        """Runs one queued write guarded against a wedged shared
        connection. aiosqlite.Connection is itself a background Thread
        processing one queued SQLite call at a time (confirmed by reading
        aiosqlite's own source) -- if that thread is stuck inside a single
        slow/hung call, nothing else queued on that connection, from any
        caller, ever completes, and there is no way to forcibly stop a
        Python thread. asyncio.timeout/wait_for alone can't fix this: it
        can only make the *caller* stop waiting, not free the thread the
        call is actually blocked on.

        Runs `coro_factory()` as its own task instead of awaiting it
        directly, and shields that task from our own wait_for timeouts
        below, so giving up on waiting for it never cancels it -- it just
        keeps running (or stays stuck) in the background while we decide
        what to do next.

        Escalation, each step only reached if the previous one didn't
        resolve the write:
          1. Wait up to WRITE_INTERRUPT_AFTER_SECONDS normally.
          2. Call conn.interrupt() (bypasses the stuck queue entirely --
             see _try_interrupt) and wait up to WRITE_REPLACE_GRACE_SECONDS
             more. This unblocks the write if the thread was stuck inside
             SQLite's own VM step execution; it does nothing if the thread
             is blocked in a lower-level OS call (fsync, a filesystem
             filter-driver stall, ...) that SQLite's interrupt flag is
             never checked during -- that's an accepted limitation, not a
             bug, which is exactly why step 3 exists as the real guarantee.
          3. Treat the connection as wedged: abandon it and replace it
             (see _replace_wedged_connection), and resolve `future` with
             ConnectionWedgedError so whoever's awaiting enqueue() doesn't
             hang forever too."""
        write_task = asyncio.ensure_future(coro_factory())

        try:
            result = await asyncio.wait_for(asyncio.shield(write_task), timeout=WRITE_INTERRUPT_AFTER_SECONDS)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            await self._handle_write_exception(e, future)
            return
        else:
            if not future.done():
                future.set_result(result)
            return

        interrupted = await self._try_interrupt()
        logger.warning(
            "aggregator writer: write exceeded %ds -- called conn.interrupt() (dispatched=%s), "
            "waiting up to %ds more before treating the connection as wedged",
            WRITE_INTERRUPT_AFTER_SECONDS, interrupted, WRITE_REPLACE_GRACE_SECONDS,
        )

        try:
            result = await asyncio.wait_for(asyncio.shield(write_task), timeout=WRITE_REPLACE_GRACE_SECONDS)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            await self._handle_write_exception(e, future)
            return
        else:
            if not future.done():
                future.set_result(result)
            logger.info("aggregator writer: write completed after interrupt -- connection was not actually wedged, just slow")
            return

        # Past both the threshold and the grace period: the underlying
        # write_task is still suspended and interrupt() didn't free it.
        # Its outcome (did it commit? partially? not at all?) is now
        # unknowable -- it's abandoned along with the connection, not
        # cancelled (cancelling it wouldn't do anything either).
        await self._replace_wedged_connection()
        if not future.done():
            future.set_exception(
                ConnectionWedgedError("shared DB connection was wedged; this write's outcome is unknown")
            )

    async def _try_interrupt(self) -> bool:
        """Attempts to unstick a wedged write via sqlite3.Connection.
        interrupt(), called from this watchdog -- never from the stuck
        write_task itself. aiosqlite's own async interrupt() is exactly
        `self._conn.interrupt()` (verified against the installed aiosqlite
        source) with no queueing through self._tx at all, unlike close(),
        so it can reach a connection whose queue is otherwise completely
        stuck. sqlite3's interrupt() is documented as safe to call from a
        different thread/task while another operation is in progress.

        Returns whether interrupt() itself was successfully invoked (not
        whether it actually unblocked the write -- the caller checks that
        separately via write_task)."""
        try:
            db = await get_db()
            await db.interrupt()
            return True
        except Exception:
            logger.exception("aggregator writer: conn.interrupt() itself raised -- connection may already be unusable")
            return False

    async def _replace_wedged_connection(self) -> None:
        """The shared connection is confirmed wedged (past both the
        interrupt threshold and the grace period after attempting
        conn.interrupt()). Does NOT call close() on it -- close() just
        queues `self._conn.close` onto the same stuck background thread
        (see aiosqlite's Connection.close()) and would hang exactly the
        same way. Abandons it outright instead (its thread leaks until
        process exit) and opens a fresh connection via db.database.
        replace_db(), which every future get_db() call -- from this
        writer, from ProcessWatcher, from any HTTP handler -- sees from
        here on.

        Escalates to a deliberate process exit once this has already
        happened MAX_CONNECTION_REPLACEMENTS times in this process's
        lifetime: repeated wedging points at a real, unrecoverable
        storage problem, not a one-off, and exiting is what lets the
        existing external supervisors (tray app / VS Code extension,
        both of which already detect and respawn a dead backend process)
        take over, instead of this process quietly leaking connections
        forever.

        replace_db() (-> init_db()) can itself raise -- confirmed live:
        "database is locked", because the connection we just abandoned
        above is never close()'d (see replace_db's own docstring for why)
        and its background thread can still be holding the WAL write
        lock at the exact moment the new connection's setup runs. That's
        not a new silent-death case: a failed replacement attempt counts
        against the same MAX_CONNECTION_REPLACEMENTS budget as a failed
        write did, and either retries -- the stale lock is usually
        transient, clearing once the abandoned thread's stuck call
        finally finishes or the OS itself gives up on it -- or falls
        through to the same deliberate-exit path above once the budget
        is exhausted. Either way this never raises back to the caller;
        start_writer()'s own try/except is only a final backstop for
        anything unforeseen, not the intended path for this."""
        while True:
            self._connection_replace_count += 1

            if self._connection_replace_count > MAX_CONNECTION_REPLACEMENTS:
                logger.critical(
                    "aggregator writer: shared DB connection has wedged/failed to replace "
                    "%d times this process lifetime -- this points at a real storage "
                    "problem, not a transient one. Exiting so the supervisor (tray app / "
                    "VS Code extension) restarts the backend fresh instead of leaking "
                    "connections indefinitely.",
                    self._connection_replace_count,
                )
                os._exit(1)

            logger.error(
                "aggregator writer: shared DB connection wedged (interrupt did not unblock it "
                "within %ds grace) -- abandoning it and opening a fresh connection "
                "(replacement #%d of %d tolerated this process lifetime)",
                WRITE_REPLACE_GRACE_SECONDS, self._connection_replace_count, MAX_CONNECTION_REPLACEMENTS,
            )
            try:
                await replace_db()
                return
            except Exception:
                logger.exception(
                    "aggregator writer: replace_db() itself raised while replacing a "
                    "wedged connection (the abandoned connection's thread may still be "
                    "holding the WAL lock) -- treating this as another failed "
                    "replacement attempt and retrying within budget"
                )
                await asyncio.sleep(1)

    async def _handle_write_exception(self, e: Exception, future: asyncio.Future) -> None:
        """Ordinary write failure (constraint violation, bad param, ...) --
        distinct from a wedge, this is a fast, clean exception, not a
        stuck call. Same rollback-then-propagate behavior this class has
        always had."""
        logger.error("aggregator writer error: %s", e)
        # Root cause of the recurring "database table is locked"
        # errors this was meant to fix: a failed write (constraint
        # violation, bad param, ...) leaves the shared aiosqlite
        # connection sitting in an open, uncommitted transaction --
        # nothing here ever called commit() for it, and Python's
        # sqlite3 doesn't auto-rollback a failed statement. Every
        # later operation on this same connection then hits "table
        # is locked" against that stuck transaction, permanently,
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
        # Aggregator's one shutdown hook (see main.py's lifespan) -- also
        # where the persistent crash-recovery file handle gets closed;
        # see _ensure_crash_recovery_file_open.
        self._close_crash_recovery_file()

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
        a flush clears the log.

        Keeps the file open across calls (see _ensure_crash_recovery_file_
        open) instead of a fresh open+close per line -- same file, same
        JSON-line format, same at-least-once guarantee, just without the
        repeated open/close syscall per real-time file event. flush()
        after every write keeps the "safe if the process dies mid-write"
        property: the line is durable on disk as soon as this call
        returns, exactly as the old open-append-close version guaranteed,
        even though the file descriptor itself now stays open longer."""
        try:
            self._ensure_crash_recovery_file_open()
            self._crash_recovery_file.write(json.dumps(event, default=str) + "\n")
            self._crash_recovery_file.flush()
        except Exception:
            logger.exception("crash recovery: failed to append event, continuing without it")
            # The handle itself may be the broken part (file moved/deleted
            # out from under us, disk error, ...) -- drop it so the next
            # call reopens fresh instead of repeatedly failing on the same
            # broken handle.
            self._close_crash_recovery_file()

    def _ensure_crash_recovery_file_open(self) -> None:
        """Opens the crash-recovery file once and keeps the handle for
        reuse. The directory-exists check is likewise done at most once
        per open, not per line -- both were real per-event syscalls before
        this fix."""
        if self._crash_recovery_file is not None:
            return
        path = _crash_recovery_path()
        if not self._crash_recovery_dir_ensured:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._crash_recovery_dir_ensured = True
        self._crash_recovery_file = open(path, "a", encoding="utf-8")

    def _close_crash_recovery_file(self) -> None:
        if self._crash_recovery_file is not None:
            try:
                self._crash_recovery_file.close()
            except Exception:
                logger.exception("crash recovery: failed to close file handle")
            finally:
                self._crash_recovery_file = None

    def _clear_crash_recovery_log(self) -> None:
        """Closes the persistent handle before unlinking -- Windows won't
        reliably delete a file that's still open under this process's own
        handle, and even where it would, leaving the old (now-unlinked)
        inode's handle open while _ensure_crash_recovery_file_open thinks
        it already has a valid handle would silently write into a deleted
        file instead of the fresh one anyone reading crash_recovery.log
        next expects. The next _append_crash_recovery_line call reopens a
        genuinely fresh file, same as before this change."""
        try:
            self._close_crash_recovery_file()
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
            await self._checkpoint()
        if self._flush_count % 20 == 0:
            await self._log_events_row_count()

    async def _checkpoint(self) -> None:
        """Runs PRAGMA wal_checkpoint(PASSIVE) on its own short-lived
        connection, deliberately not the shared get_db() singleton and not
        routed through enqueue() -- so it executes concurrently with the
        single writer queue instead of through it, and a slow checkpoint
        can never block Aggregator/ProcessWatcher/VlawFileHandler writes
        that share that queue. Best-effort: any failure here is logged and
        swallowed, never raised into flush_buffers.

        PRAGMA wal_checkpoint(PASSIVE) returns a single row of
        (busy, log, checkpointed): `busy` is 1 if something else held the
        WAL and blocked a full checkpoint, `log` is the WAL's total frame
        count, `checkpointed` is how many of those frames this call
        actually checkpointed. Until now that row was never fetched --
        `await conn.execute(...)` alone discards it -- so there was no way
        to tell a checkpoint that ran but did nothing (busy=1,
        checkpointed < log, under write contention -- the original WAL-
        growth theory) apart from one that genuinely had nothing to do
        (log==0). Logging that row, plus the actual .db-wal file size on
        disk, turns "checkpoint took 0.46s" from a duration with no
        meaning into a verifiable catch-up/falling-behind signal."""
        start = time.monotonic()
        try:
            conn = await aiosqlite.connect(DB_PATH)
            try:
                cur = await conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                row = await cur.fetchone()
                busy, log_frames, checkpointed_frames = row if row else (None, None, None)
            finally:
                await conn.close()

            wal_path = Path(f"{DB_PATH}-wal")
            try:
                wal_bytes = wal_path.stat().st_size if wal_path.exists() else 0
            except OSError:
                wal_bytes = None

            logger.info(
                "[TIMING] checkpoint result: busy=%s log_frames=%s checkpointed_frames=%s "
                "wal_bytes=%s wal_mb=%s",
                busy, log_frames, checkpointed_frames, wal_bytes,
                round(wal_bytes / (1024 * 1024), 2) if wal_bytes is not None else None,
            )
        except Exception:
            logger.exception("aggregator: dedicated-connection WAL checkpoint failed")
        finally:
            elapsed = time.monotonic() - start
            logger.info(f"[TIMING] checkpoint took {elapsed:.2f}s")

    async def _log_events_row_count(self) -> None:
        """Cheap diagnostic: how large the events table has grown, logged
        every 20th flush. Uses get_read_db() -- a short-lived read-only
        connection, same pattern API handlers already use -- rather than
        get_db()/enqueue(), so this never competes with the writer queue
        either. Best-effort: any failure here is logged and swallowed,
        never raised into flush_buffers."""
        try:
            conn = await get_read_db()
            try:
                cur = await conn.execute("SELECT COUNT(*) AS n FROM events")
                row = await cur.fetchone()
                count = row["n"] if row else None
            finally:
                await conn.close()
            logger.info(f"[TIMING] events table row count: {count}")
        except Exception:
            logger.exception("aggregator: events row count check failed")

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
            start = time.monotonic()
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
                            e["agent_id"], e["session_id"], e["event_type"], e["path"],
                            json.dumps(e.get("detail") or {}), e.get("severity", "low"),
                            e.get("pid"), e.get("event_source"),
                            _format_created_at(e.get("timestamp")),
                        )
                        for e in batch
                    ],
                )
                await db.commit()
            finally:
                elapsed = time.monotonic() - start
                logger.info(f"[TIMING] write_batch took {elapsed:.2f}s, n_events={len(batch)}")

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
        evidence = await self.alerter.check_credential_access(
            event["agent_id"], event["path"], event_id=event_id, session_id=event["session_id"],
            pid=pid,
        )
        if evidence:
            evidence_store.add_evidence(evidence)

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
