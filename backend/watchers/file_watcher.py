"""Watches policy scope_directories and credential_paths for file activity.
Uses PollingObserver (not Observer/inotify) so it works reliably under
Docker Desktop on Windows, where native filesystem events are unreliable."""

import asyncio
import os
import time

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

from core.attributor import Attributor
from core.red_lines import RedLines, is_agent_config_path, is_mcp_config_path
from db.database import get_db

POLL_INTERVAL_SECONDS = 3

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
        self.red_lines = RedLines()

    def on_any_event(self, event):
        if event.is_directory:
            return

        event_type = EVENT_TYPE_MAP.get(event.event_type, "file_read")
        path = event.dest_path if getattr(event, "dest_path", "") else event.src_path

        asyncio.run_coroutine_threadsafe(
            self._handle_event(path, event_type), self.loop
        )

    async def _handle_event(self, path: str, event_type: str) -> None:
        # _find_owning_agent_pid does a synchronous psutil.process_iter() scan
        # over every running process — offloaded via run_in_executor (same
        # pattern as ProcessWatcher.poll/NetworkWatcher.poll) so it never
        # blocks the event loop that also serves HTTP and runs the scheduler.
        loop = asyncio.get_event_loop()
        pid, confidence = await loop.run_in_executor(None, _find_owning_agent_pid, self.attributor)
        agent_name = self.attributor.get_agent_for_pid(pid) if pid else None

        if agent_name is None:
            return  # no known agent active — nothing to attribute this to

        agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
        session_id = await self.attributor.sessions.touch(agent_id)

        await self._check_red_lines(agent_id, agent_name, path, event_type, session_id)
        await self._check_config_exec(agent_id, agent_name, path, event_type, session_id)
        await self._check_mcp_config_write(agent_id, path, event_type)

        await self.aggregator.ingest_file_event({
            "agent_id": agent_id,
            "session_id": session_id,
            "path": path,
            "event_type": event_type,
            "attribution_confidence": confidence,
        })

    async def _check_red_lines(self, agent_id: int, agent_name: str, path: str, event_type: str, session_id: str | None = None) -> None:
        """Red Line rules run before any policy-based check for the same
        event (the aggregator's check_out_of_scope_access/
        check_credential_access run later, either immediately or on
        flush)."""
        is_write = event_type in ("file_write", "file_delete")

        await self.red_lines.check_ssh_access(agent_id, agent_name, path, session_id=session_id)
        if is_write:
            db = await get_db()
            await self.red_lines.check_claude_cache_write(agent_id, agent_name, path, db, session_id=session_id)
        else:
            await self.red_lines.check_env_outside_workspace(agent_id, agent_name, path, session_id=session_id)
            await self.red_lines.check_cross_project_read(agent_id, agent_name, path, session_id=session_id)

    async def _check_config_exec(self, agent_id: int, agent_name: str, path: str, event_type: str, session_id: str | None = None) -> None:
        """RL7b (CVE-2025-59536 pattern): a project config write followed
        within RedLines.CONFIG_EXEC_WINDOW_SECONDS by a spawn/write elsewhere.
        State is shared at module level (core.red_lines._pending_config_writes)
        so process_watcher.py's proc_spawn events can also consume a write
        recorded here, and vice versa."""
        is_write = event_type in ("file_write", "file_delete")

        if is_agent_config_path(path) and is_write:
            self.red_lines.record_config_write(agent_id, path)
            return

        pending = self.red_lines.pop_pending_config_write(agent_id)
        if pending is None:
            return
        if path == pending["path"]:
            return  # the config write's own event, not a separate trigger

        prior_approved_sessions = await self._count_prior_approved_sessions(agent_id)
        await self.red_lines.check_malicious_config_execution(
            agent_id, agent_name,
            config_path=pending["path"], config_write_ts=pending["ts"],
            triggered_event_path=path, triggered_event_ts=time.time(),
            prior_approved_sessions=prior_approved_sessions,
            session_id=session_id,
        )

    async def _check_mcp_config_write(self, agent_id: int, path: str, event_type: str) -> None:
        """RL8 (CVE-2026-21852 pattern, MCP attack surface): records a
        .mcp.json write as a pending trigger candidate. The correlating
        MCP-connection half runs in watchers/mcp_watcher.py, which consumes
        this via RedLines.pop_pending_mcp_config_write — see
        core/red_lines.py::check_mcp_auto_approval for the full rule."""
        is_write = event_type in ("file_write", "file_delete")
        if is_write and is_mcp_config_path(path):
            self.red_lines.record_mcp_config_write(agent_id, path)

    async def _count_prior_approved_sessions(self, agent_id: int) -> int:
        db = await get_db()
        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE agent_id = ? AND ended_at IS NOT NULL",
            (agent_id,),
        )
        row = await cur.fetchone()
        return row["c"] if row else 0


def start_file_watcher(
    attributor: Attributor, aggregator, watch_paths: list[str], non_recursive_paths: list[str] | None = None,
) -> PollingObserver:
    """Starts a PollingObserver watching each path in watch_paths
    (recursively) plus non_recursive_paths (top-level only — used for RL8's
    .mcp.json, which lives at the project root; watching the whole project
    tree recursively just to catch one root-level file would be a much
    bigger scope/perf change than RL8 calls for). Returns the observer so
    the caller can stop() it on shutdown."""
    loop = asyncio.get_event_loop()

    observer = PollingObserver(timeout=POLL_INTERVAL_SECONDS)
    handler = VlawFileHandler(attributor, aggregator, loop)

    for path in watch_paths:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            observer.schedule(handler, expanded, recursive=True)

    for path in non_recursive_paths or []:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            observer.schedule(handler, expanded, recursive=False)

    observer.start()
    return observer
