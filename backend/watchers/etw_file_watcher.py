"""Real-time, kernel-level file event capture via ETW (Event Tracing for
Windows), consuming the Microsoft-Windows-Kernel-File provider directly —
exact PID, no polling, no missed events. This is the primary file event
source; see file_watcher.py for how it's wired in and what it falls back to
when it can't run (not admin, package unavailable, unsupported OS, ...).

Built against pyetwkit (https://github.com/m96-chan/PyETWkit), introspected
directly against the installed package rather than assumed from docs. Two
things could NOT be verified in the environment this was built in, since
both require an actual elevated trace session to observe real events, and
that environment had no Administrator privileges available:

  1. Exact property names for the file path on each event. Verified via
     `wevtutil gp Microsoft-Windows-Kernel-File` that the task/event ID
     values below are correct (NameCreate=10, NameDelete=11, Create=12,
     Write=16, ..., DeletePath=26, RenamePath=27 — see EVENT_ID_TASK_NAMES),
     but the manifest dump on this machine didn't include per-event
     property/template names. PATH_PROPERTY_CANDIDATES is checked in
     priority order against each event rather than assuming one exact name,
     specifically to absorb this uncertainty; _log_unresolved_schema (rate
     limited) surfaces it if none of the candidates match on a real machine,
     so a real property name can be added without needing to re-derive this
     from scratch.
  2. That pyetwkit's KernelFlags/event delivery behaves as documented under
     real load. Given that (see README history), every per-event operation
     below is wrapped so a single bad or unexpected event can never take
     down the consumer thread or the backend.

Run this on a real elevated Windows session before trusting its output —
see file_watcher.py's module docstring for the fallback tiers this sits
above.
"""

import asyncio
import logging
import threading
import time

from core.attributor import Attributor

logger = logging.getLogger("vlaw")

try:
    import pyetwkit
    PYETWKIT_AVAILABLE = True
except ImportError:
    pyetwkit = None
    PYETWKIT_AVAILABLE = False

# Task/event IDs for Microsoft-Windows-Kernel-File, confirmed against this
# provider's actual installed manifest via `wevtutil gp
# Microsoft-Windows-Kernel-File` (task value == event value for every entry
# checked). Not all 25+ tasks the provider defines are used here — only the
# ones that represent an agent actually creating, changing, or removing a
# file; Read/DirEnum/Flush/QueryInformation/FSCTL etc. are deliberately left
# out of both maps below, so pyetwkit's event_ids() filter (see
# _build_listener) never even delivers them to this process.
TASK_NAME_CREATE = 10
TASK_NAME_DELETE = 11
TASK_CREATE = 12       # handle open/create -- fires on plain opens too, not
                        # just new files; used only to seed the FileObject
                        # cache below, never emitted as its own event.
TASK_WRITE = 16
TASK_SET_INFORMATION = 17
TASK_SET_DELETE = 18
TASK_RENAME = 19
TASK_DELETE_PATH = 26
TASK_RENAME_PATH = 27

EVENT_ID_TO_TYPE = {
    TASK_NAME_CREATE: "file_write",
    TASK_NAME_DELETE: "file_delete",
    TASK_WRITE: "file_write",
    TASK_SET_INFORMATION: "file_write",
    TASK_SET_DELETE: "file_delete",
    TASK_RENAME: "file_write",
    TASK_DELETE_PATH: "file_delete",
    TASK_RENAME_PATH: "file_write",
}

# Events whose own properties are checked for a direct path, used to seed
# the FileObject -> path correlation cache (see _process_event). Most
# Kernel-File I/O events (Write, SetInformation, Rename, ...) only carry a
# FileObject handle, not a path -- Create/NameCreate are the ones that
# reliably see the name at the moment the handle is opened.
CACHE_SEED_EVENT_IDS = {TASK_NAME_CREATE, TASK_CREATE}

SUBSCRIBED_EVENT_IDS = sorted(set(EVENT_ID_TO_TYPE) | CACHE_SEED_EVENT_IDS)

# Checked in priority order against each event (see module docstring, point 1).
PATH_PROPERTY_CANDIDATES = ("FileName", "OpenPath", "TargetFileName", "FilePath")
FILEOBJECT_PROPERTY = "FileObject"

MAX_FILEOBJECT_CACHE_ENTRIES = 4096
MAX_INFLIGHT_EVENTS = 1000  # caps scheduled-but-not-yet-run callback coroutines
EVENT_POLL_TIMEOUT_SECONDS = 1.0
_UNRESOLVED_SCHEMA_LOG_INTERVAL_SECONDS = 300  # rate-limit the point-1 diagnostic


class ETWFileWatcher:
    """Consumes Microsoft-Windows-Kernel-File in a dedicated background
    thread and dispatches matching events onto the asyncio loop via
    asyncio.run_coroutine_threadsafe. Never touches the loop directly from
    the ETW thread, and never lets an ETW-side failure reach the caller
    after start() returns True -- from that point on, any problem is
    logged and this watcher simply stops producing events."""

    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self._callback = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._listener = None
        self._stop_event = threading.Event()
        self._started_event = threading.Event()
        self._start_error: str | None = None
        self._inflight = threading.Semaphore(MAX_INFLIGHT_EVENTS)
        self._dropped_count = 0
        self._file_object_cache: dict[int, str] = {}
        self._last_unresolved_schema_log = 0.0

    def set_callback(self, fn) -> None:
        """fn: async def on_file_event(pid: int, path: str, event_type: str,
        timestamp: float)"""
        self._callback = fn

    def start(self) -> bool:
        """Starts the ETW session in a background thread. Returns True if
        the session came up, False if it couldn't (package missing, not
        admin, unsupported OS, or any other failure) -- callers (see
        file_watcher.py) are expected to fall back to a lower tier on False,
        never to treat it as fatal."""
        if not PYETWKIT_AVAILABLE:
            logger.info("ETW file watcher unavailable: pyetwkit is not installed")
            return False
        if self._callback is None:
            logger.error("ETW file watcher started without a callback registered")
            return False

        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            logger.error("ETW file watcher must be started from a thread with a running asyncio loop")
            return False

        self._stop_event.clear()
        self._started_event.clear()
        self._start_error = None
        self._thread = threading.Thread(target=self._run, name="vlaw-etw-file-watcher", daemon=True)
        self._thread.start()

        # The actual session.start() happens on the background thread (ETW
        # session objects are bound to the thread that creates them); wait
        # for that thread to tell us whether it came up so start() can give
        # the caller a synchronous yes/no to decide fallback on.
        if not self._started_event.wait(timeout=10):
            logger.error("ETW file watcher timed out starting")
            return False

        if self._start_error is not None:
            logger.info("ETW file watcher could not start (%s) — falling back", self._start_error)
            return False

        logger.info("ETW file watcher started (Microsoft-Windows-Kernel-File)")
        return True

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # --- background thread -------------------------------------------

    def _run(self) -> None:
        try:
            provider = pyetwkit.FileProvider.kernel().event_ids(SUBSCRIBED_EVENT_IDS)
            self._listener = pyetwkit.EtwListener(providers=[provider], name="vlaw-kernel-file")
            self._listener.start()
        except Exception as e:
            # Most commonly OSError ("administrator privileges required") --
            # covered generically since pyetwkit's own docs only promise
            # OSError for that one case, and this must never propagate.
            self._start_error = str(e)
            self._started_event.set()
            return

        self._started_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    for event in self._listener.events(timeout=EVENT_POLL_TIMEOUT_SECONDS):
                        if self._stop_event.is_set():
                            break
                        self._process_event(event)
                except Exception:
                    logger.exception("ETW file watcher: error reading from session, continuing")
                    time.sleep(0.5)  # avoid a hot loop if events() itself starts failing repeatedly
        finally:
            try:
                self._listener.stop()
            except Exception:
                pass

    def _process_event(self, event) -> None:
        try:
            event_id = event.event_id
            file_object = event.get_u64(FILEOBJECT_PROPERTY)

            if event_id in CACHE_SEED_EVENT_IDS:
                path = self._extract_path(event)
                if path and file_object is not None:
                    self._cache_file_object(file_object, path)

            event_type = EVENT_ID_TO_TYPE.get(event_id)
            if event_type is None:
                return  # a cache-seed-only event (e.g. plain Create/open), not itself reportable

            path = self._extract_path(event)
            if path is None and file_object is not None:
                path = self._file_object_cache.get(file_object)
            if not path:
                return  # can't safely report a file event with no resolved path

            pid = event.process_id
            if not pid:
                return

            # Performance filter per spec: only agent-caused file events are
            # worth the round trip through attribution + DB writes; get_agent_for_pid
            # is the same cached, thread-safe lookup process_watcher.py/network_watcher.py
            # already call from their own executor threads.
            agent_name = self.attributor.get_agent_for_pid(pid)
            if agent_name is None:
                return

            timestamp = event.timestamp_unix
            self._dispatch(pid, path, event_type, timestamp)
        except Exception:
            logger.exception("ETW file watcher: failed to process one event, skipping it")

    def _extract_path(self, event) -> str | None:
        for name in PATH_PROPERTY_CANDIDATES:
            value = event.get_string(name)
            if value:
                return value
        self._log_unresolved_schema(event)
        return None

    def _log_unresolved_schema(self, event) -> None:
        now = time.monotonic()
        if now - self._last_unresolved_schema_log < _UNRESOLVED_SCHEMA_LOG_INTERVAL_SECONDS:
            return
        self._last_unresolved_schema_log = now
        try:
            available = list(event.properties.keys())
        except Exception:
            available = ["<unavailable>"]
        logger.warning(
            "ETW file watcher: none of %s matched this event's schema (event_id=%s); "
            "actual properties: %s — see etw_file_watcher.py module docstring",
            PATH_PROPERTY_CANDIDATES, getattr(event, "event_id", "?"), available,
        )

    def _cache_file_object(self, file_object: int, path: str) -> None:
        if len(self._file_object_cache) >= MAX_FILEOBJECT_CACHE_ENTRIES:
            # Cheap unbounded-growth guard, not true LRU -- good enough for
            # a best-effort correlation cache that's naturally self-healing
            # (a fresh Create/NameCreate reseeds any entry that gets evicted).
            self._file_object_cache.pop(next(iter(self._file_object_cache)))
        self._file_object_cache[file_object] = path

    def _dispatch(self, pid: int, path: str, event_type: str, timestamp: float) -> None:
        if not self._inflight.acquire(blocking=False):
            self._dropped_count += 1
            if self._dropped_count % 100 == 1:
                logger.warning(
                    "ETW file watcher: dropping events, %d in-flight events already queued "
                    "(dropped %d total) — the asyncio loop can't keep up",
                    MAX_INFLIGHT_EVENTS, self._dropped_count,
                )
            return

        asyncio.run_coroutine_threadsafe(
            self._invoke_callback(pid, path, event_type, timestamp), self._loop
        )

    async def _invoke_callback(self, pid: int, path: str, event_type: str, timestamp: float) -> None:
        try:
            await self._callback(pid, path, event_type, timestamp)
        except Exception:
            logger.exception("ETW file watcher: callback failed for pid=%s path=%s", pid, path)
        finally:
            self._inflight.release()
