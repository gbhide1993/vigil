"""Watches policy scope_directories and credential_paths for file activity.
Uses PollingObserver (not Observer/inotify) so it works reliably under
Docker Desktop on Windows, where native filesystem events are unreliable."""

import asyncio
import os

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from core.attributor import Attributor

POLL_INTERVAL_SECONDS = 1

EVENT_TYPE_MAP = {
    "created": "file_write",
    "modified": "file_write",
    "moved": "file_write",
    "deleted": "file_delete",
}


def _find_owning_agent_pid(attributor: Attributor) -> tuple[int | None, str]:
    """Best-effort: scan running processes for known agents. Filesystem
    events don't carry the triggering PID directly, so we attribute to
    whichever known agent process is currently active.

    Returns (pid, confidence). If more than one distinct known agent is
    running concurrently, attribution is ambiguous — we still pick the
    first match but flag confidence as "low" so it's auditable rather
    than silently presented as certain."""
    matches: list[int] = []
    seen_agents: set[str] = set()

    for proc in psutil.process_iter(["pid", "name"]):
        agent = attributor.get_agent_for_pid(proc.info["pid"])
        if agent:
            matches.append(proc.info["pid"])
            seen_agents.add(agent)

    if not matches:
        return None, "high"

    confidence = "low" if len(seen_agents) > 1 else "high"
    return matches[0], confidence


class VlawFileHandler(FileSystemEventHandler):
    def __init__(self, attributor: Attributor, aggregator, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.attributor = attributor
        self.aggregator = aggregator
        self.loop = loop

    def on_any_event(self, event):
        if event.is_directory:
            return

        event_type = EVENT_TYPE_MAP.get(event.event_type, "file_read")
        path = event.dest_path if getattr(event, "dest_path", "") else event.src_path

        asyncio.run_coroutine_threadsafe(
            self._handle_event(path, event_type), self.loop
        )

    async def _handle_event(self, path: str, event_type: str) -> None:
        pid, confidence = _find_owning_agent_pid(self.attributor)
        agent_name = self.attributor.get_agent_for_pid(pid) if pid else None

        if agent_name is None:
            return  # no known agent active — nothing to attribute this to

        agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
        session_id = await self.attributor.sessions.touch(agent_id)

        await self.aggregator.ingest_file_event({
            "agent_id": agent_id,
            "session_id": session_id,
            "path": path,
            "event_type": event_type,
            "attribution_confidence": confidence,
        })


def start_file_watcher(attributor: Attributor, aggregator, watch_paths: list[str]) -> PollingObserver:
    """Starts a PollingObserver watching each path in watch_paths.
    Returns the observer so the caller can stop() it on shutdown."""
    loop = asyncio.get_event_loop()

    observer = PollingObserver(timeout=POLL_INTERVAL_SECONDS)
    handler = VlawFileHandler(attributor, aggregator, loop)

    for path in watch_paths:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            observer.schedule(handler, expanded, recursive=True)

    observer.start()
    return observer
