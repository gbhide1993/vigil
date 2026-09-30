"""Watches policy scope_directories and credential_paths for file activity.

Three tiers, tried in priority order once at startup:
  1. ETW (watchers.etw_file_watcher.ETWFileWatcher) — kernel-level, exact
     PID, no polling delay. Requires Administrator privileges and the
     pyetwkit package; see etw_file_watcher.py's module docstring for what
     has and hasn't been verified about it.
  2. Native watchdog Observer (ReadDirectoryChangesW-backed, the same
     backend `watchdog` already ships and used to be avoided here entirely
     — see point 3) — real-time delivery, no polling delay, but like ETW's
     predecessor here, no PID from the OS notification itself.
     _find_owning_agent_pid's open-handle refinement (see below) narrows
     the old "whichever known agent happens to be running" guess down using
     which candidate process actually has the file open right now.
  3. PollingObserver — unchanged from before this feature existed. Used
     under Docker Desktop, where native ReadDirectoryChangesW notifications
     don't reliably cross the WSL2 host-mount boundary (the original reason
     this file used PollingObserver exclusively), and as the last-resort
     fallback if tier 2 also fails to start for any other reason.

Whichever tier starts successfully is used for the life of the process —
there's no dynamic re-promotion if a higher tier stops working mid-session,
matching "use ETW if available, else fall back" from the feature spec.
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from core.attributor import Attributor
from core.burst_detector import BurstDetector
from core.correlation_engine import CorrelationEngine
from core.evidence import AttributionChain, AttributionConfidence, VigilEvidence
from core.evidence_store import evidence_store
from core.red_lines import RedLines, is_agent_config_path, is_mcp_config_path, register_agent_workspace
from db.database import get_db
from watchers.etw_file_watcher import ETWFileWatcher

_CONFIDENCE_BY_NAME = {
    "HIGH": AttributionConfidence.HIGH,
    "MEDIUM": AttributionConfidence.MEDIUM,
    "LOW": AttributionConfidence.LOW,
    "UNKNOWN": AttributionConfidence.UNKNOWN,
}

logger = logging.getLogger("vlaw")

POLL_INTERVAL_SECONDS = 3

EVENT_TYPE_MAP = {
    "created": "file_write",
    "modified": "file_write",
    "moved": "file_write",
    "deleted": "file_delete",
}

# Dedicated pool for _find_owning_agent_pid's per-event open_files() calls
# (see _handle_polled_event) -- deliberately NOT the loop's shared default
# executor (main.py sets that to 50 workers for ProcessWatcher/NetworkWatcher
# etc.). psutil.Process.open_files() is one of the more expensive psutil
# calls on Windows (full handle-table enumeration); under sustained
# real-time file-event volume it can keep every worker in a shared pool
# busy, which delays *other* unrelated executor-dispatched work queued
# behind it (a plausible contributor to scheduler-lag symptoms that have
# nothing to do with file attribution). Isolating it here bounds its
# blast radius to this one pool without changing what it computes or how
# often it runs.
_OPEN_HANDLE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="vlaw-open-handle"
)


class _AgentPidCache:
    """Background-refreshed {pid: agent_name} snapshot of every currently
    running known-agent process.

    _find_owning_agent_pid used to call psutil.process_iter() and resolve
    every single running process on every file event — on a real desktop
    (measured: ~375 processes), each _walk_parent_chain call costs
    50-100ms (psutil.Process() + up to 10 levels of .parent()/.name(),
    apparently genuinely this expensive under real-world conditions, not a
    bug in this codebase), which adds up to 15-20+ seconds for a full scan.
    That's always been true of this scan (nothing new here made
    _walk_parent_chain itself slower) — it just never mattered while
    PollingObserver was the only tier and nothing needed sub-second
    latency. It directly breaks this feature's 500ms target for the
    real-time tiers, so the scan is moved off the file-event critical path
    entirely: this class re-scans on its own timer, and
    _find_owning_agent_pid only ever reads whatever's currently cached
    (up to REFRESH_INTERVAL_SECONDS stale, never blocking on a fresh scan).

    A daemon thread, like ETWFileWatcher's — not explicitly joined on
    shutdown (there's nowhere clean to hang that off the watchdog Observer/
    PollingObserver/ETWFileWatcher objects start_file_watcher returns,
    and letting it run for up to one more refresh cycle during shutdown is
    harmless)."""

    # This class's own docstring above already documents the cost: a full
    # refresh (psutil.process_iter() + get_named_agent_for_pid per process)
    # measured 50-100ms per process, "15-20+ seconds for a full scan" on a
    # real desktop (~375 processes). At the old 3s interval this thread was
    # therefore doing another multi-second scan almost as soon as the
    # previous one finished -- effectively always busy, not periodically
    # refreshing -- which py-spy confirmed as a sustained-CPU contributor
    # (thread caught mid-scan on every sample taken). 30s gives the scan
    # comfortable headroom to actually finish with idle time in between,
    # cutting this thread's busy fraction roughly in half to two-thirds,
    # at the cost of the real-time-tier cache being up to 30s (not 3s)
    # stale in the worst case -- the same order of staleness already
    # accepted elsewhere (ProcessWatcher's own poll interval is 30s).
    REFRESH_INTERVAL_SECONDS = 30

    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self._map: dict[int, str] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._refresh()  # pay the first scan's cost once, up front, not on the first file event
        self._thread = threading.Thread(target=self._run, name="vlaw-agent-pid-cache", daemon=True)
        self._thread.start()

    def snapshot(self) -> dict[int, str]:
        return self._map

    def _run(self) -> None:
        while not self._stop_event.wait(self.REFRESH_INTERVAL_SECONDS):
            self._refresh()

    def _refresh(self) -> None:
        try:
            fresh = {}
            for proc in psutil.process_iter(["pid", "name"]):
                # get_named_agent_for_pid, not get_agent_for_pid: this loop
                # runs against every process on the machine, and
                # get_agent_for_pid's behavioural fallback (a synchronous DB
                # round trip) would run for every one of them that isn't a
                # name-matched known agent -- see its docstring.
                agent = self.attributor.get_named_agent_for_pid(proc.info["pid"])
                if agent:
                    fresh[proc.info["pid"]] = agent
            self._map = fresh
        except Exception:
            logger.exception("agent pid cache refresh failed, keeping previous snapshot")


def _find_owning_agent_pid(pid_cache: _AgentPidCache, path: str | None = None) -> tuple[int | None, str]:
    """Best-effort: pick from the currently-cached known-agent processes
    (see _AgentPidCache) — refined, when `path` is given (tier 2 only, see
    module docstring), by checking which of those candidate processes
    actually has `path` open right now (see _refine_pid_by_open_handle): a
    write's file handle is often still open, or was only just closed, by
    the time this runs on the real-time tier, which lets this catch
    attribution the plain "first known agent" guess gets wrong whenever
    more than one agent is running at once. Not run for the polling tier —
    by the time a poll fires, several seconds after the write, the handle
    is essentially always already closed, so the extra psutil calls would
    just be overhead with no accuracy benefit.

    Returns (pid, confidence). If more than one distinct known agent is
    running concurrently and the open-handle refinement didn't narrow it
    down to exactly one, we still pick the first match but flag confidence
    as "low" so it's auditable rather than silently presented as certain."""
    agent_map = pid_cache.snapshot()
    if not agent_map:
        return None, "high"

    matches = list(agent_map.keys())
    seen_agents = set(agent_map.values())

    if path is not None and len(matches) > 1:
        refined = _refine_pid_by_open_handle(matches, path)
        if refined is not None:
            return refined, "high"

    confidence = "low" if len(seen_agents) > 1 else "high"
    return matches[0], confidence


def _refine_pid_by_open_handle(candidate_pids: list[int], path: str) -> int | None:
    """Checks each candidate agent PID's currently-open file handles for
    `path`, returning the one PID that actually has it open, if exactly one
    does. Best-effort, not exact: a fast open-write-close can already have
    closed the handle by the time this runs (psutil.Process.open_files()
    reflects live handles only), and a process with the file open for an
    unrelated reason would false-positive. Never raises — a process that
    has since exited or denies access is just skipped, not reported."""
    normalized_target = os.path.normcase(os.path.abspath(path))
    found: list[int] = []
    for pid in candidate_pids:
        try:
            for f in psutil.Process(pid).open_files():
                if os.path.normcase(os.path.abspath(f.path)) == normalized_target:
                    found.append(pid)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return found[0] if len(found) == 1 else None


def _log_dispatch_exception(future: "asyncio.Future", path: str) -> None:
    """run_coroutine_threadsafe dispatch is fire-and-forget (on_any_event
    fires from watchdog's own notifier thread and can't await the result),
    so without this an exception in the dispatched coroutine would
    otherwise vanish silently — this just makes that visible in the log
    instead of changing the fire-and-forget behaviour itself."""
    try:
        future.result()
    except asyncio.CancelledError:
        pass
    except Exception:
        logger.exception("file watcher: unhandled error processing event for %s", path)


class VlawFileHandler(FileSystemEventHandler):
    def __init__(
        self,
        attributor: Attributor,
        aggregator,
        loop: asyncio.AbstractEventLoop,
        pid_cache: "_AgentPidCache | None",
        use_pid_heuristic: bool = False,
        process_watcher=None,
        network_watcher=None,
    ):
        super().__init__()
        self.attributor = attributor
        self.aggregator = aggregator
        self.loop = loop
        self.pid_cache = pid_cache
        self.red_lines = RedLines()
        # True only for the native (ReadDirectoryChangesW) tier — see
        # _find_owning_agent_pid's docstring for why the polling tier skips
        # the open-handle refinement.
        self.use_pid_heuristic = use_pid_heuristic
        # WHO confidence, Stage 1: independent of any single event's own
        # pid-guess attribution above. process_watcher/network_watcher are
        # optional (None when this handler isn't wired into main.py's
        # scheduler, e.g. in isolated tests) — check_burst() is a no-op
        # without them.
        self.process_watcher = process_watcher
        self.network_watcher = network_watcher
        self._burst_detector = BurstDetector()
        self._correlation_engine = CorrelationEngine()

    def on_any_event(self, event):
        """Tiers 2/3 entry point — native Observer and PollingObserver both
        emit this same watchdog FileSystemEvent shape."""
        if event.is_directory:
            return

        event_type = EVENT_TYPE_MAP.get(event.event_type, "file_read")
        path = event.dest_path if getattr(event, "dest_path", "") else event.src_path

        future = asyncio.run_coroutine_threadsafe(
            self._handle_polled_event(path, event_type), self.loop
        )
        future.add_done_callback(lambda f: _log_dispatch_exception(f, path))

    async def _handle_polled_event(self, path: str, event_type: str) -> None:
        # _find_owning_agent_pid itself is now just a cache read (see
        # _AgentPidCache) plus, for tier 2, a handful of per-candidate
        # open_files() calls -- offloaded via run_in_executor since
        # open_files() is blocking I/O, but on _OPEN_HANDLE_EXECUTOR (its
        # own small dedicated pool), not the loop's shared default executor
        # ProcessWatcher/NetworkWatcher use -- see _OPEN_HANDLE_EXECUTOR's
        # comment for why.
        loop = asyncio.get_event_loop()
        guess_path = path if self.use_pid_heuristic else None
        pid, confidence = await loop.run_in_executor(
            _OPEN_HANDLE_EXECUTOR, _find_owning_agent_pid, self.pid_cache, guess_path
        )
        event_source = "realtime_heuristic" if self.use_pid_heuristic else "poll"
        await self.handle_file_event(path, event_type, event_source, pid, confidence, time.time())

    async def handle_etw_event(self, pid: int, path: str, event_type: str, timestamp: float) -> None:
        """Tier 1 entry point — registered as ETWFileWatcher's callback.
        pid is already exact and already filtered to a known/suspected
        agent (see etw_file_watcher.ETWFileWatcher._process_event), so this
        skips the _find_owning_agent_pid guess entirely."""
        await self.handle_file_event(path, event_type, "etw", pid, "high", timestamp)

    async def handle_file_event(
        self,
        path: str,
        event_type: str,
        event_source: str,
        pid: int | None,
        confidence: str,
        timestamp: float | None = None,
    ) -> None:
        # Recorded regardless of whether this specific event resolves to a
        # known agent below — burst+correlation (check_burst) is a second,
        # independent attribution path meant to catch activity the
        # per-event pid-guess above can't, so it needs every file change,
        # not just the ones this path already attributed.
        await self._burst_detector.record_event(path, event_type)

        agent_name = self.attributor.get_agent_for_pid(pid) if pid else None

        if agent_name is None:
            return  # no known/suspected agent active — nothing to attribute this to

        is_unidentified = agent_name == "unidentified_agent"
        behaviour_confidence = self.attributor.get_behaviour_score_for_pid(pid) if is_unidentified else None

        agent_id = await self.attributor.get_or_create_agent(agent_name, pid, confidence=behaviour_confidence)
        session_id = await self.attributor.sessions.touch(agent_id)

        await self._check_red_lines(agent_id, agent_name, path, event_type, session_id)
        await self._check_config_exec(agent_id, agent_name, path, event_type, session_id)
        await self._check_mcp_config_write(agent_id, path, event_type)

        event_dict = {
            "agent_id": agent_id,
            "session_id": session_id,
            "path": path,
            "event_type": event_type,
            "attribution_confidence": confidence,
            "pid": pid,
            "event_source": event_source,
            "timestamp": timestamp if timestamp is not None else time.time(),
        }

        if self.aggregator is not None:
            await self.aggregator.ingest_file_event(event_dict)
        else:
            # Defensive fallback per spec — VlawFileHandler is always
            # constructed with a real aggregator today (see
            # start_file_watcher), so this path is not expected to run in
            # practice. Writes directly, bypassing buffering entirely.
            await self._write_direct(event_dict)

    async def check_burst(self) -> None:
        """Scheduled every 30s (see main.py) — independent of
        handle_file_event's own per-event pid-guess attribution. Correlates
        a burst of file changes against recent network connections (LLM API
        domains) and the current process table via CorrelationEngine; only
        produces evidence when at least one of those independent layers
        actually corroborates, per compute_confidence's own gating."""
        burst = await self._burst_detector.flush_burst()
        if burst is None:
            return
        if self.process_watcher is None or self.network_watcher is None:
            logger.warning("check_burst: process_watcher/network_watcher not wired in -- dropping burst")
            return

        result = self._correlation_engine.compute_confidence(
            burst,
            self.network_watcher.get_recent_events(window_secs=90),
            self.process_watcher.get_snapshot(),
        )

        evidence = VigilEvidence(
            what=f"{burst['event_count']} files modified",
            when=datetime.fromtimestamp(burst["start_time"], tz=timezone.utc),
            attribution=AttributionChain(
                confidence=_CONFIDENCE_BY_NAME[result["who_confidence"]],
                chain=result["observation_layers"],
                basis="; ".join(result["attribution_basis"]) or "No corroborating signals observed.",
                attributed_agent=result["who"],
            ),
        )
        evidence_store.add_evidence(evidence)

    async def _write_direct(self, event: dict) -> None:
        """Last-resort direct write used only when self.aggregator is None
        (see handle_file_event) — no buffering, no batching, exactly the
        one-INSERT-plus-commit-per-event pattern buffering exists to avoid,
        acceptable only because this path shouldn't normally run at all."""
        db = await get_db()
        await db.execute(
            """
            INSERT INTO events
                (agent_id, session_id, event_type, path, detail, severity, pid, event_source)
            VALUES (?, ?, ?, ?, ?, 'low', ?, ?)
            """,
            (
                event["agent_id"],
                event["session_id"],
                event["event_type"],
                event["path"],
                json.dumps({"attribution_confidence": event.get("attribution_confidence", "high")}),
                event.get("pid"),
                event.get("event_source"),
            ),
        )
        await db.commit()

    async def _check_red_lines(self, agent_id: int, agent_name: str, path: str, event_type: str, session_id: str | None = None) -> None:
        """Red Line rules run before any policy-based check for the same
        event (the aggregator's check_out_of_scope_access/
        check_credential_access run later, either immediately or on
        flush)."""
        register_agent_workspace(agent_id, path)

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


def _schedule_paths(observer, handler: VlawFileHandler, watch_paths: list[str], non_recursive_paths: list[str] | None) -> None:
    for path in watch_paths:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            observer.schedule(handler, expanded, recursive=True)

    for path in non_recursive_paths or []:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            observer.schedule(handler, expanded, recursive=False)


def start_file_watcher(
    attributor: Attributor, aggregator, watch_paths: list[str], non_recursive_paths: list[str] | None = None,
    process_watcher=None, network_watcher=None,
):
    """Starts the highest-priority file-watching tier that will come up
    (see module docstring) and returns (watcher, handler). The watcher half
    always exposes .stop() / .join(timeout) / .is_alive() regardless of
    which tier it is — main.py's shutdown sequence and /health endpoint
    treat it uniformly and need no changes for any of this. The handler
    half is returned so main.py can schedule its check_burst() method
    (Stage 1 burst+correlation) periodically, the same way it schedules the
    other watchers' poll() — that scheduler doesn't exist yet at the point
    in main.py's startup sequence where this function is called.

    process_watcher/network_watcher are threaded through to the handler
    (see VlawFileHandler.check_burst) purely so it can read their
    get_snapshot()/get_recent_events() — nothing here calls into them."""
    loop = asyncio.get_event_loop()

    etw_watcher = ETWFileWatcher(attributor)
    etw_handler = VlawFileHandler(
        attributor, aggregator, loop, pid_cache=None,
        process_watcher=process_watcher, network_watcher=network_watcher,
    )
    etw_watcher.set_callback(etw_handler.handle_etw_event)
    if etw_watcher.start():
        return etw_watcher, etw_handler

    # Only built for tiers 2/3 (ETW never guesses a pid, so never needs
    # this) -- starts its own background refresh thread, see _AgentPidCache.
    pid_cache = _AgentPidCache(attributor)
    pid_cache.start()

    # VLAW_HOST_ROOT is set under Docker Desktop, where the host filesystem
    # is mounted read-only through WSL2 — native ReadDirectoryChangesW
    # notifications don't reliably cross that boundary (this is the
    # original, still-valid reason this file used PollingObserver
    # exclusively before ETW/native support existed), so Docker keeps using
    # polling unconditionally rather than attempting tier 2 first.
    use_native = not os.environ.get("VLAW_HOST_ROOT")

    if use_native:
        try:
            candidate = Observer()
            handler = VlawFileHandler(
                attributor, aggregator, loop, pid_cache, use_pid_heuristic=True,
                process_watcher=process_watcher, network_watcher=network_watcher,
            )
            _schedule_paths(candidate, handler, watch_paths, non_recursive_paths)
            candidate.start()
            logger.info("file watcher: using native real-time observer (ReadDirectoryChangesW)")
            return candidate, handler
        except Exception:
            logger.exception("file watcher: native observer failed to start, falling back to polling")

    observer = PollingObserver(timeout=POLL_INTERVAL_SECONDS)
    handler = VlawFileHandler(
        attributor, aggregator, loop, pid_cache, use_pid_heuristic=False,
        process_watcher=process_watcher, network_watcher=network_watcher,
    )
    _schedule_paths(observer, handler, watch_paths, non_recursive_paths)
    observer.start()
    logger.info("file watcher: using polling observer")
    return observer, handler
