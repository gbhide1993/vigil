"""Event aggregation engine. Raw OS events are too noisy to write directly
to the events table, so file and network events are buffered in time
windows and collapsed before being persisted. Credential-path file events
and process spawns bypass aggregation entirely and are written immediately."""

import json
import time
from pathlib import Path

from core.alerter import Alerter
from db.database import get_db

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
        elapsed and writes a single aggregated event per (agent, scope)."""
        now = time.time()
        db = await get_db()

        expired_file_keys = [
            k for k, v in self._file_buffer.items()
            if now - v["window_start"] >= FILE_WINDOW_SECONDS
        ]
        for key in expired_file_keys:
            agent_id, directory = key
            buf = self._file_buffer.pop(key)
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
            await self.alerter.check_out_of_scope_access(agent_id, directory, event_id=cur.lastrowid)

        expired_net_keys = [
            k for k, v in self._net_buffer.items()
            if now - v["window_start"] >= NET_WINDOW_SECONDS
        ]
        for key in expired_net_keys:
            agent_id, host = key
            buf = self._net_buffer.pop(key)
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

        if expired_file_keys or expired_net_keys:
            await db.commit()

    async def _write_credential_event(self, event: dict) -> None:
        """Credential paths are never aggregated — always individual,
        immediately processed events."""
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
        await self.alerter.check_credential_access(event["agent_id"], event["path"], event_id=cur.lastrowid)
