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
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from core.attribution import UNATTRIBUTED_AGENT, agent_for_path
from core.attributor import Attributor
from core.burst_detector import BurstDetector
from core.correlation_engine import CorrelationEngine
from core.evidence import AttributionChain, AttributionConfidence, VigilEvidence
from core.evidence_store import evidence_store
from core.feature_flags import CORE_ONLY
from core import watch_stats
from core.ignore_rules import ignore_and_count
from core.own_paths import is_own_path
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

# Upper bound on raw file events handed to the event loop and not yet handled
# (watchdog threads submit one coroutine per raw event). Beyond this, new raw
# events are dropped and counted (core/watch_stats.py, stated in the report)
# instead of queueing without limit. Ignored folders never reach this point.
MAX_PENDING_FILE_DISPATCH = 2000

# watchdog's raw event names -> the change type stored with the event
# (EVENT_TYPE_MAP above folds created / modified / moved into "file_write",
# so without this the create / write / move distinction would be lost).
CHANGE_MAP = {"created": "create", "modified": "write", "moved": "move", "deleted": "delete"}

# _refine_pid_by_open_handle's psutil.Process.open_files() calls run in a
# disposable subprocess (watchers/_open_handle_worker.py), not in this
# process at all -- not even on a dedicated thread pool, which is what an
# earlier version of this fix used. That pool isolated the call's *blast
# radius* within this process, but not the underlying risk: on Windows,
# open_files()'s C extension does not release the GIL around
# NtQueryObject, which has a documented bug where querying a handle tied
# to a pending synchronous I/O operation (e.g. a named pipe) can hang
# indefinitely -- and since the GIL is held, that freezes the *entire*
# process, not just the thread that called it. Confirmed live via py-spy:
# every thread in that dedicated pool was simultaneously stuck here during
# a real multi-minute app freeze. A subprocess has its own GIL, so a hang
# there can never block this process's event loop, and it can be
# hard-killed (proc.kill()) out from under a stuck call -- something no
# amount of same-process thread-pool restructuring can do. See
# _refine_pid_by_open_handle and watchers.process_watcher._run_process_scan
# (the same pattern, used for the same reason, for a different psutil call).
_OPEN_HANDLE_WORKER_PATH = str(Path(__file__).parent / "_open_handle_worker.py")
# Short and deliberately much tighter than process_watcher's 18s scan
# timeout -- this runs on the real-time file-event path and must fail fast
# rather than add visible lag to every event while an agent is active.
_OPEN_HANDLE_TIMEOUT_SECONDS = 2.5

# Caps how many open-handle subprocess spawns can be in flight at once.
# Confirmed necessary by testing, not theoretical: a burst of concurrent
# real-time events with 2+ known agents live (e.g. heavy write activity
# from two coding agents at once) spawned dozens of these concurrently,
# which under real resource contention pushed individual spawn times as
# high as 14s (measured), caused a pile-up of ~24 near-simultaneous
# timeouts, a 3+ minute stall in this process's own scheduled-job
# logging, and -- worst -- subprocesses that were still orphaned and
# running minutes after the parent process had already exited (process
# creation itself was so delayed under contention that the timeout-and-
# kill logic had already given up and abandoned the handle before the OS
# had even finished creating the process). Capping concurrency bounds all
# of that: at most this many spawns/kills/reaps can be in progress at
# once, so a burst degrades to queueing-then-fallback instead of
# system-wide contention. See _refine_pid_by_open_handle for where the
# semaphore is held and released.
_OPEN_HANDLE_MAX_CONCURRENT = 2
_OPEN_HANDLE_SEMAPHORE = asyncio.Semaphore(_OPEN_HANDLE_MAX_CONCURRENT)
# A call that can't get a slot within this long gives up on the subprocess
# entirely for this event and falls back to the existing low-confidence
# heuristic -- this is a real-time attribution path, not a job queue, so
# queueing indefinitely for a slot would just trade one kind of lag for
# another.
_OPEN_HANDLE_SEMAPHORE_WAIT_SECONDS = 1.0

# Short-lived cache keyed by (normalized path, sorted candidate pids) --
# secondary to the concurrency cap above, not a substitute for it: cuts
# down how often a subprocess needs to spawn at all during a burst (the
# same path is often re-checked by multiple near-simultaneous events for
# the same write), rather than bounding the cost of each individual spawn.
# TTL deliberately short -- this is a live open-handle check, not
# something that should go stale across genuinely distinct events.
_OPEN_HANDLE_CACHE_TTL_SECONDS = 0.4
_open_handle_cache: dict[tuple[str, tuple[int, ...]], tuple[float, int | None]] = {}


def _prune_open_handle_cache() -> None:
    """Called after every write -- keeps this from growing unboundedly
    over a long-running process. Cheap: entries are short-lived by design,
    so this dict never holds more than a burst's worth at a time."""
    now = time.monotonic()
    expired = [
        key for key, (ts, _result) in _open_handle_cache.items()
        if now - ts >= _OPEN_HANDLE_CACHE_TTL_SECONDS
    ]
    for key in expired:
        del _open_handle_cache[key]


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
    harmless).

    UPDATE: the 50-100ms/process, 15-20+ second figures below described
    _refresh() calling get_named_agent_for_pid with no pid_snapshot, which
    falls back to opening a fresh psutil.Process(pid) handle per
    parent-chain level for every process on the machine -- confirmed via
    py-spy as the sustained ~0.96-core/GIL-starvation source, stalling
    /api/health for 3s and /api/sessions for 16s on first call. _refresh()
    now builds one pid_snapshot per call and resolves every PID from it
    (_walk_parent_chain_from_snapshot, zero further psutil calls) -- see
    its own docstring for current numbers. REFRESH_INTERVAL_SECONDS left
    at 30 for now; the busy-fraction reasoning below no longer applies at
    the new per-refresh cost, but changing the interval is a separate
    decision, not made here."""

    # Historical cost model this interval was originally chosen against
    # (no longer accurate for _refresh() specifically -- see UPDATE above):
    # a full refresh (psutil.process_iter() + get_named_agent_for_pid per
    # process) measured 50-100ms per process, "15-20+ seconds for a full
    # scan" on a real desktop (~375 processes). At the old 3s interval this
    # thread was therefore doing another multi-second scan almost as soon
    # as the previous one finished -- effectively always busy, not
    # periodically refreshing -- which py-spy confirmed as a sustained-CPU
    # contributor (thread caught mid-scan on every sample taken). 30s gave
    # the scan comfortable headroom to actually finish with idle time in
    # between, at the cost of the real-time-tier cache being up to 30s
    # (not 3s) stale in the worst case -- the same order of staleness
    # already accepted elsewhere (ProcessWatcher's own poll interval is 30s).
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
        """Builds one {pid: {"name", "ppid"}} snapshot from a single
        psutil.process_iter() pass, then resolves every PID's attribution
        from that in-memory dict via Attributor._walk_parent_chain_from_snapshot
        (zero further psutil calls) -- same pattern ProcessWatcher already
        uses for _gather_spawn_info's get_agent_for_pid calls. Previously
        this called get_named_agent_for_pid with no pid_snapshot, which falls
        back to _walk_parent_chain's per-level psutil.Process(pid).parent()
        path: one fresh OS process handle open per parent-chain level, for
        every process on the machine, every refresh. py-spy confirmed this
        thread as the sustained-CPU/GIL-starvation source (see
        get_agent_for_pid's docstring for why the snapshot path exists)."""
        try:
            pid_snapshot: dict[int, dict] = {}
            for proc in psutil.process_iter(["pid", "name", "ppid"]):
                pid = proc.info.get("pid")
                if pid is None:
                    continue
                pid_snapshot[pid] = {
                    "name": proc.info.get("name") or "",
                    "ppid": proc.info.get("ppid") or 0,
                }

            fresh = {}
            for pid in pid_snapshot:
                # get_named_agent_for_pid, not get_agent_for_pid: this loop
                # runs against every process on the machine, and
                # get_agent_for_pid's behavioural fallback (a synchronous DB
                # round trip) would run for every one of them that isn't a
                # name-matched known agent -- see its docstring.
                agent = self.attributor.get_named_agent_for_pid(pid, pid_snapshot=pid_snapshot)
                if agent:
                    fresh[pid] = agent
            self._map = fresh
        except Exception:
            logger.exception("agent pid cache refresh failed, keeping previous snapshot")


# Returned by _find_owning_agent_pid in place of a confidence when two or more agents were running and nothing
# narrows the write down to one of them.
AMBIGUOUS = "ambiguous"


async def _find_owning_agent_pid(pid_cache: _AgentPidCache, path: str | None = None) -> tuple[int | None, str]:
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
    down to exactly one (including on a subprocess timeout/failure -- see
    _refine_pid_by_open_handle), no agent is picked: it returns
    (None, AMBIGUOUS) and the write is recorded as unattributed.

    Confidence is never "high" for this (native / polling observer) tier; see
    the comment where it is chosen below."""
    agent_map = pid_cache.snapshot()
    if not agent_map:
        return None, "low"      # no agent running: the caller drops the event

    matches = list(agent_map.keys())
    seen_agents = set(agent_map.values())

    if path is not None and len(matches) > 1:
        refined = await _refine_pid_by_open_handle(matches, path)
        if refined is not None:
            return refined, "medium"

    # Never "high" here: this tier does not know which process wrote the
    # file, only which agents were running. "low" = more than one agent was
    # running; "medium" = one agent was running, but the writer was not
    # verified (a change you made yourself looks the same).
    if len(seen_agents) > 1:
        # Two or more agents and nothing to tell them apart: do not pick one (the first in the cache used to get the
        # write, which is how Claude Code's changes ended up under an idle Codex). The caller records the write as
        # unattributed (core/attribution.py).
        return None, AMBIGUOUS
    return matches[0], "medium"


async def _refine_pid_by_open_handle(candidate_pids: list[int], path: str) -> int | None:
    """Checks each candidate agent PID's currently-open file handles for
    `path`, returning the one PID that actually has it open, if exactly one
    does. Best-effort, not exact: a fast open-write-close can already have
    closed the handle by the time this runs (psutil.Process.open_files()
    reflects live handles only), and a process with the file open for an
    unrelated reason would false-positive.

    Runs the actual psutil call in a disposable subprocess (see
    _OPEN_HANDLE_WORKER_PATH's module docstring for why: the GIL-holding
    NtQueryObject hang risk on Windows means this can't safely run even on
    a dedicated same-process thread) -- gated by a short-lived cache and a
    concurrency cap (see _OPEN_HANDLE_CACHE_TTL_SECONDS/_OPEN_HANDLE_
    SEMAPHORE's comments for why both are needed, confirmed by testing
    under real burst load). Never raises, never blocks the caller beyond
    _OPEN_HANDLE_SEMAPHORE_WAIT_SECONDS + _OPEN_HANDLE_TIMEOUT_SECONDS -- a
    cache miss that can't get a slot, a timed-out subprocess, or any other
    failure all just return None, same as "couldn't narrow it down", which
    _find_owning_agent_pid already treats as a low-confidence first match
    rather than an error."""
    cache_key = (os.path.normcase(os.path.abspath(path)), tuple(sorted(candidate_pids)))
    cached = _open_handle_cache.get(cache_key)
    if cached is not None and time.monotonic() - cached[0] < _OPEN_HANDLE_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        await asyncio.wait_for(
            _OPEN_HANDLE_SEMAPHORE.acquire(), timeout=_OPEN_HANDLE_SEMAPHORE_WAIT_SECONDS
        )
    except asyncio.TimeoutError:
        logger.warning(
            "open-handle check: all %d concurrent slot(s) busy after waiting %.1fs -- "
            "skipping this event's subprocess, falling back to first-match/low-confidence attribution",
            _OPEN_HANDLE_MAX_CONCURRENT, _OPEN_HANDLE_SEMAPHORE_WAIT_SECONDS,
        )
        return None

    try:
        result = await _run_open_handle_subprocess(candidate_pids, path)
    finally:
        # Only reached once _run_open_handle_subprocess has returned -- and
        # it never returns until the subprocess is confirmed reaped (see
        # its own docstring) on every exit path, success, timeout, or
        # error. Releasing any earlier (e.g. right after wait_for on the
        # communicate() call, before confirming the kill actually landed)
        # is exactly the gap that let orphaned subprocesses slip through
        # under contention during testing.
        _OPEN_HANDLE_SEMAPHORE.release()

    _open_handle_cache[cache_key] = (time.monotonic(), result)
    _prune_open_handle_cache()
    return result


async def _run_open_handle_subprocess(candidate_pids: list[int], path: str) -> int | None:
    """Does the actual spawn/wait/parse for _refine_pid_by_open_handle --
    split out so the semaphore-holding caller can rely on this never
    returning until the subprocess is confirmed gone, on every exit path.

    Wraps subprocess creation *and* communicate() in the same timeout, not
    just communicate(): under real contention (confirmed by testing),
    create_subprocess_exec() itself can be the slow part -- a 2.5s-only
    bound around communicate() still lets total wall-clock time blow past
    the budget whenever spawning itself is what's slow. If the timeout
    fires before `proc` even gets assigned, there is genuinely nothing to
    kill yet -- an unavoidable gap given asyncio's API, not a different
    bug -- but every other case (proc assigned, anything after) is always
    kill()-ed and wait()-ed before returning."""
    if getattr(sys, "frozen", False):
        args = [sys.executable, "--open-handle-worker"]
    else:
        args = [sys.executable, _OPEN_HANDLE_WORKER_PATH]
    args.append(path)
    args.append(",".join(str(p) for p in candidate_pids))

    proc: "asyncio.subprocess.Process | None" = None

    async def _spawn_and_communicate():
        nonlocal proc
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return await proc.communicate()

    try:
        stdout, _stderr = await asyncio.wait_for(
            _spawn_and_communicate(), timeout=_OPEN_HANDLE_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        logger.warning(
            "open-handle check timed out after %.1fs and was killed -- "
            "falling back to first-match/low-confidence attribution",
            _OPEN_HANDLE_TIMEOUT_SECONDS,
        )
        return None
    except Exception:
        if proc is not None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
        logger.exception("open-handle check subprocess failed -- falling back to first-match/low-confidence attribution")
        return None

    try:
        result = json.loads(stdout.decode("utf-8", errors="replace"))
    except Exception:
        logger.warning("open-handle worker returned unparseable output")
        return None
    if result.get("error"):
        logger.warning("open-handle worker error: %s", result["error"])
    matched = result.get("matched_pid")
    return int(matched) if matched is not None else None


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
        # Raw events submitted to the loop and not yet handled; see MAX_PENDING_FILE_DISPATCH.
        self._pending_dispatch = 0
        self._pending_lock = threading.Lock()

    def on_any_event(self, event):
        """Tiers 2/3 entry point — native Observer and PollingObserver both
        emit this same watchdog FileSystemEvent shape."""
        if event.is_directory:
            return

        event_type = EVENT_TYPE_MAP.get(event.event_type, "file_read")
        path = event.dest_path if getattr(event, "dest_path", "") else event.src_path
        if is_own_path(path):
            return   # Vigil's own install / data folder: never an agent's activity
        if ignore_and_count(path):
            return   # generated / dependency folder: dropped before any other work (core/ignore_rules.py)
        with self._pending_lock:
            over_limit = self._pending_dispatch >= MAX_PENDING_FILE_DISPATCH
            if not over_limit:
                self._pending_dispatch += 1
        if over_limit:
            watch_stats.add_dropped("overload")
            return

        future = asyncio.run_coroutine_threadsafe(
            self._handle_polled_event(path, event_type, CHANGE_MAP.get(event.event_type)), self.loop
        )
        future.add_done_callback(lambda f: self._dispatch_done(f, path))

    def _dispatch_done(self, future, path: str) -> None:
        with self._pending_lock:
            self._pending_dispatch -= 1
        _log_dispatch_exception(future, path)

    async def _handle_polled_event(self, path: str, event_type: str, change: str | None = None) -> None:
        # _find_owning_agent_pid itself is now just a cache read (see
        # _AgentPidCache) plus, for tier 2, a possible subprocess call for
        # open-handle refinement -- see _refine_pid_by_open_handle and
        # _OPEN_HANDLE_WORKER_PATH's comment for why that runs in a
        # disposable subprocess rather than on any same-process thread.
        # A change in an agent's own folder (~/.claude, ~/.codex) is given to that agent when it is running, before
        # the guess below: the guess picks the first agent it finds, which is how Claude Code's checkpoint files ended
        # up under Codex. Marked event_source "path" (core/attribution.py); anything else keeps the guess.
        path_agent = agent_for_path(path)
        if path_agent and self.pid_cache is not None:
            owner_pid = next((p for p, name in self.pid_cache.snapshot().items() if name == path_agent), None)
            if owner_pid is not None:
                await self.handle_file_event(path, event_type, "path", owner_pid, "medium", time.time(), change=change)
                return

        guess_path = path if self.use_pid_heuristic else None
        pid, confidence = await _find_owning_agent_pid(self.pid_cache, guess_path)
        event_source = "realtime_heuristic" if self.use_pid_heuristic else "poll"
        if confidence == AMBIGUOUS:
            agents_active = max(2, len(set(self.pid_cache.snapshot().values())))
            await self.handle_file_event(path, event_type, event_source, None, "low", time.time(), change=change,
                                         agents_active=agents_active)
            return
        await self.handle_file_event(path, event_type, event_source, pid, confidence, time.time(), change=change)

    async def handle_etw_event(self, pid: int, path: str, event_type: str, timestamp: float, change: str | None = None) -> None:
        """Tier 1 entry point — registered as ETWFileWatcher's callback.
        pid is already exact and already filtered to a known/suspected
        agent (see etw_file_watcher.ETWFileWatcher._process_event), so this
        skips the _find_owning_agent_pid guess entirely."""
        await self.handle_file_event(path, event_type, "etw", pid, "high", timestamp, change=change)

    async def handle_file_event(
        self,
        path: str,
        event_type: str,
        event_source: str,
        pid: int | None,
        confidence: str,
        timestamp: float | None = None,
        change: str | None = None,
        agents_active: int | None = None,
    ) -> None:
        """agents_active is set only for a write that cannot be told apart between that many running agents: it is
        then recorded under the "unattributed" agent (pid None, confidence low)."""
        # Safety filter for every tier (native, polling and ETW): changes
        # inside Vigil's own install folder or data folder (its database,
        # logs, updates) are never recorded, however the watch list was
        # configured.
        if is_own_path(path):
            return
        # Safety net for callers that did not filter earlier (the ETW tier
        # filters before attribution; the watchdog tiers in on_any_event).
        if ignore_and_count(path):
            return

        # Recorded regardless of whether this specific event resolves to a
        # known agent below — burst+correlation (check_burst) is a second,
        # independent attribution path meant to catch activity the
        # per-event pid-guess above can't, so it needs every file change,
        # not just the ones this path already attributed.
        await self._burst_detector.record_event(path, event_type)

        if agents_active:
            agent_name = UNATTRIBUTED_AGENT
            agent_id = await self.attributor.get_or_create_unattributed_agent()
        else:
            agent_name = self.attributor.get_agent_for_pid(pid) if pid else None

            if agent_name is None:
                return  # no known/suspected agent active — nothing to attribute this to

            is_unidentified = agent_name == "unidentified_agent"
            behaviour_confidence = self.attributor.get_behaviour_score_for_pid(pid) if is_unidentified else None

            agent_id = await self.attributor.get_or_create_agent(agent_name, pid, confidence=behaviour_confidence)
        session_id = await self.attributor.sessions.touch(agent_id)

        if not CORE_ONLY:
            await self._check_red_lines(agent_id, agent_name, path, event_type, session_id)
            await self._check_config_exec(agent_id, agent_name, path, event_type, session_id)
            await self._check_mcp_config_write(agent_id, path, event_type)

        event_dict = {
            "agent_id": agent_id,
            "session_id": session_id,
            "path": path,
            "event_type": event_type,
            "attribution_confidence": confidence,
            "change": change,
            "pid": pid,
            "event_source": event_source,
            "timestamp": timestamp if timestamp is not None else time.time(),
        }
        if agents_active:
            event_dict["agents_active"] = agents_active

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


def _watch_key(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(path))).replace("\\", "/").rstrip("/")


def _watch_registry(observer) -> dict:
    """{normalised path: watchdog ObservedWatch} for every recursive watch
    scheduled on this observer, kept on the observer itself so a watch can
    be removed later (Observer.unschedule needs the watch object)."""
    registry = getattr(observer, "_vlaw_watches", None)
    if registry is None:
        registry = {}
        observer._vlaw_watches = registry
    return registry


def watched_paths(observer) -> list[str]:
    """The folders this observer is recursively watching right now (what the
    live scope API reports as `observed_paths`). Empty for an observer
    without a folder list (the ETW tier)."""
    registry = getattr(observer, "_vlaw_watches", None) or {}
    return sorted(getattr(w, "path", key) for key, w in registry.items())


def watch_folder(observer, handler, path: str) -> bool:
    """Starts watching `path` (recursively) on the RUNNING observer, with no
    restart. Returns True if it is now watched. False when there is nothing
    to schedule on (the ETW tier has no folder list: it already sees every
    change made by a recognised agent anywhere) or the folder is gone."""
    if not hasattr(observer, "schedule"):
        return False
    expanded = os.path.expanduser(path)
    if not os.path.isdir(expanded):
        return False
    registry = _watch_registry(observer)
    key = _watch_key(expanded)
    if key in registry:
        return True
    registry[key] = observer.schedule(handler, expanded, recursive=True)
    return True


def unwatch_folder(observer, path: str) -> bool:
    """Stops watching `path`. True if a watch was removed."""
    if not hasattr(observer, "unschedule"):
        return False
    watch = _watch_registry(observer).pop(_watch_key(path), None)
    if watch is None:
        return False
    observer.unschedule(watch)
    return True


def _schedule_paths(observer, handler: VlawFileHandler, watch_paths: list[str], non_recursive_paths: list[str] | None) -> None:
    for path in watch_paths:
        expanded = os.path.expanduser(path)
        if os.path.isdir(expanded):
            registry = _watch_registry(observer)
            key = _watch_key(expanded)
            if key not in registry:    # never schedule the same folder twice (duplicate events)
                registry[key] = observer.schedule(handler, expanded, recursive=True)

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
