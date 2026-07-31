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
import time
from pathlib import Path

from core.alerter import Alerter
from db.database import get_db

logger = logging.getLogger("vlaw")

FILE_WINDOW_SECONDS = 5
NET_WINDOW_SECONDS = 60

CREDENTIAL_PATTERNS = [".env", ".ssh", ".aws", ".pem", ".key"]


def _is_credential_path(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in CREDENTIAL_PATTERNS)


class Aggregator:
    def __init__(self):
        # (agent_id, dir) -> {"count": int, "window_start": float, "event_type": str, "paths": set}
        self._file_buffer: dict[tuple, dict] = {}
        # (agent_id, host) -> {"request_count": int, "bytes_out": int, "window_start": float}
        self._net_buffer: dict[tuple, dict] = {}
        self.alerter = Alerter()

        self._write_queue: asyncio.Queue = asyncio.Queue()
        self._writer_task: asyncio.Task | None = None

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
        """event: {agent_id, session_id, path, event_type, attribution_confidence?}"""
        path = event["path"]
        confidence = event.get("attribution_confidence", "high")

        if _is_credential_path(path):
            await self._write_credential_event(event)
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
                        (agent_id, session_id, event_type, path, detail, file_count, severity)
                    VALUES (?, ?, ?, ?, ?, ?, 'low')
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

    async def _write_credential_event(self, event: dict) -> None:
        """Credential paths are never aggregated — always individual,
        immediately processed events. Routed through enqueue() like
        flush_buffers() above."""
        async def _write():
            db = await get_db()
            cur = await db.execute(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, file_count, severity)
                VALUES (?, ?, 'cred_access', ?, ?, 1, 'high')
                """,
                (
                    event["agent_id"],
                    event["session_id"],
                    event["path"],
                    json.dumps({
                        "event_type": event["event_type"],
                        "attribution_confidence": event.get("attribution_confidence", "high"),
                    }),
                ),
            )
            await db.commit()
            return cur.lastrowid

        event_id = await self.enqueue(_write)
        await self.alerter.check_credential_access(
            event["agent_id"], event["path"], event_id=event_id, session_id=event["session_id"],
        )
