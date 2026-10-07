"""FastAPI app entry point. Startup sequence:
1. Init SQLite DB and run schema
2. Load policy from vlaw-policy.json
3. Validate RSA license (14-day trial grace period if no license file)
4. Start PollingObserver for file watching
5. Start APScheduler jobs: process_watcher (3s), network_watcher (5s),
   aggregator flush (5s), baseline update (hourly)
6. Serve on port 7422
"""

import json
import sys
import os

# Sentinel re-invocation for the process-scan and open-handle workers (see
# watchers.process_watcher._run_process_scan and
# watchers.file_watcher._refine_pid_by_open_handle). In a frozen build,
# sys.executable is this very exe, not a python.exe, and neither worker's
# .py file was ever bundled as a loose file for a subprocess to exec -- so
# the callers spawn [sys.executable, "--<worker>-worker", ...] instead,
# re-invoking this same exe. Handled here, before anything else (including
# get_base_path()/BASE_DIR setup and the single-instance lock in lifespan()
# further down) runs, since a second full app instance would otherwise just
# hit that lock and exit without ever producing the JSON the parent expects.
# Dev mode (python run_native.py) never passes these arguments -- both
# callers only use them when sys.frozen is set -- so this is a no-op there.
#
# sys.argv[2:] (not [1:]) is passed through to each worker's main(): this
# process's real argv is [exe, "--<worker>-worker", "<rest of the args>"],
# so argv[1] itself is the sentinel, not the worker's own arguments.
if len(sys.argv) > 1 and sys.argv[1] == "--process-scan-worker":
    from watchers._process_scan_worker import main as _run_process_scan_worker
    _run_process_scan_worker(sys.argv[2:])
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--open-handle-worker":
    from watchers._open_handle_worker import main as _run_open_handle_worker
    _run_open_handle_worker(sys.argv[2:])
    sys.exit(0)


def get_base_path() -> str:
    """Directory for user-writable files (db, policy, logs, license).

    Frozen (PyInstaller .exe): %LOCALAPPDATA%\\V-LAW. The installer places
    the exe under Program Files, which a non-elevated process (the tray
    spawns the backend unelevated) cannot write to, so data must live
    somewhere else — the standard per-user writable location survives
    reinstalls/rebuilds the same way a next-to-exe folder would. Script
    mode: this file's directory.
    """
    if getattr(sys, "frozen", False):
        local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(local_app_data, "V-LAW")
    return os.path.dirname(os.path.abspath(__file__))


def bundled_path(relative: str) -> str:
    """Path to a read-only asset bundled into the .exe (e.g. schema.sql).

    Frozen: PyInstaller unpacks bundled data into sys._MEIPASS at
    runtime. Script mode: resolves relative to this file's directory.
    """
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, relative)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative)


BASE_DIR = get_base_path()
os.makedirs(BASE_DIR, exist_ok=True)

# Other modules (db.database, config.policy, license.license_service) read
# these env vars at import time to build their path defaults, so they must
# be set before those modules are imported.
os.environ.setdefault("VLAW_DATA_DIR", os.path.join(BASE_DIR, "data"))
os.environ.setdefault("VLAW_POLICY_FILE", os.path.join(BASE_DIR, "policy", "vlaw-policy.json"))
os.environ.setdefault("VLAW_LICENSE_FILE", os.path.join(BASE_DIR, ".vlaw-license"))

import asyncio
import concurrent.futures
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, APIRouter, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from api import agents, alerts, analytics_api, chain_routes, config_api, digest_api, events, evidence, export, git_routes, mcp_routes, platform_routes, sessions
from config.policy import load_policy
from core.aggregator import Aggregator
from core.attributor import Attributor
from core.baseline import Baseline
from core.config_auditor import audit_all_configs
from core.feature_flags import CORE_ONLY
from core.insights import get_insights
from core.red_lines import SESSION_LAUNCH_DIR
from db.database import DB_PATH, close_db, get_db, get_read_db, init_db
from license.license_service import LicenseService
from watchers.file_watcher import start_file_watcher
from watchers.mcp_watcher import McpWatcher
from watchers.network_watcher import NetworkWatcher
from watchers.process_watcher import ProcessWatcher

LOG_PATH = os.path.join(BASE_DIR, "vlaw-backend.log")
logging.basicConfig(
    level=os.environ.get("VLAW_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("vlaw")
logger.info("V-LAW backend starting. BASE_DIR=%s", BASE_DIR)

VERSION = "0.9.0"
PORT = int(os.environ.get("VLAW_PORT", 7422))

_state: dict = {}


DEFAULT_POLICY = {
    "approved_agents": [],
    "approved_network_destinations": [
        "localhost", "127.0.0.1",
        "api.anthropic.com", "statsig.anthropic.com",
        "api2.cursor.sh", "api.openai.com",
        "copilot-proxy.githubusercontent.com",
        "github.com", "pypi.org", "registry.npmjs.org",
    ],
    "scope_directories": [],
    "never_scope_directories": [],
    "credential_paths": [".ssh", ".aws"],
    "mcp_connections": [],
    "command_execution": {
        "dangerous_commands": ["curl", "wget", "nc", "ssh", "netcat"]
    },
    "exceptions": [],
    "risk_acceptance": [],
}


def build_watch_paths(policy: dict) -> tuple[list[str], list[str]]:
    """Builds (watch_paths, red_line_non_recursive_dirs) for the file
    watcher. Extracted out of the lifespan startup sequence so it can be
    unit tested without booting the full app — see
    tests/test_watch_paths.py. Behavior is otherwise unchanged from what
    used to be inlined in lifespan() below.

    VLAW_HOST_ROOT is set to /host in docker-compose.yml, where the
    read-only host filesystem is mounted. Policy paths are defined from
    the host's perspective (e.g. /src), so they need that prefix to
    resolve inside the container. Empty by default for native (non-Docker)
    runs, where policy paths already resolve directly.
    """
    host_root = os.environ.get("VLAW_HOST_ROOT", "")
    scope_directories = policy.get("scope_directories", [])
    scope_dirs = [host_root + p for p in scope_directories]
    credential_paths = policy.get("credential_paths", [])
    credential_dirs = [
        p for p in credential_paths
        if p.endswith("/") or p.endswith("\\") or p.startswith("~")
    ]
    # Flat credential file patterns (".env", "*.pem", "*.key", ...) have no
    # directory component, so the filter above never turns them into a
    # watched directory — a policy of credential_paths=[".env"] would
    # otherwise never cause anything to be watched at all, and a .env
    # modification in the project would silently never reach the
    # credential-access pipeline. When credential_paths has any entries
    # (there's something to match against), also watch the project root
    # (SESSION_LAUNCH_DIR) and every configured scope directory, so a flat
    # pattern still has somewhere to fire from. Appended here in their
    # pre-host_root form (matching how scope_directories/SESSION_LAUNCH_DIR
    # are expressed everywhere else in this function) since host_root is
    # applied once, below, to the whole credential_dirs list — prefixing it
    # here too would double it under Docker (VLAW_HOST_ROOT set).
    if credential_paths:
        credential_dirs.append(str(SESSION_LAUNCH_DIR))
        credential_dirs.extend(scope_directories)

    # Red Line rules 1 and 3 (SSH directory access, Claude hidden cache
    # writes) must fire regardless of policy configuration, so their
    # directories are always watched — independent of whatever the user
    # has set in credential_paths/scope_directories. RL7b (project config
    # execution, CVE-2025-59536 pattern) needs the active project's own
    # .claude/.cursor/.vscode config dirs watched too — these live under
    # the session's launch directory (core.red_lines.SESSION_LAUNCH_DIR),
    # not under the user's home dir like the other red-line paths.
    red_line_dirs = [
        host_root + os.path.expanduser("~/.ssh/"),
        host_root + os.path.expanduser("~/.claude/file-history/"),
        host_root + str(SESSION_LAUNCH_DIR / ".claude"),
        host_root + str(SESSION_LAUNCH_DIR / ".cursor"),
        host_root + str(SESSION_LAUNCH_DIR / ".vscode"),
    ]
    # RL8 (MCP auto-approval, CVE-2026-21852 pattern) needs .mcp.json writes
    # at the project root — watched non-recursively so this doesn't balloon
    # into watching the entire project tree just to catch one root-level file.
    # SESSION_LAUNCH_DIR is now also covered recursively above (via
    # credential_dirs, when credential_paths is non-empty) so .env/*.key
    # files in subdirectories of the project root are caught too — this
    # non-recursive entry stays for RL8's own narrower purpose.
    red_line_non_recursive_dirs = [host_root + str(SESSION_LAUNCH_DIR)]
    watch_paths = scope_dirs + [host_root + p for p in credential_dirs] + red_line_dirs
    return watch_paths, red_line_non_recursive_dirs


def _ensure_default_policy() -> None:
    policy_path = os.environ["VLAW_POLICY_FILE"]
    if os.path.exists(policy_path):
        return
    os.makedirs(os.path.dirname(policy_path), exist_ok=True)
    with open(policy_path, "w") as f:
        json.dump(DEFAULT_POLICY, f, indent=2)
    logger.info("created default policy at %s", policy_path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    import os as _vigil_os
    import sys as _vigil_sys

    _lock_path = _vigil_os.path.join(_vigil_os.path.dirname(__file__),
                                '..', 'data', 'vigil.lock')
    _lock_path = _vigil_os.path.abspath(_lock_path)
    _vigil_os.makedirs(_vigil_os.path.dirname(_lock_path), exist_ok=True)

    try:
        _lock_file = open(_lock_path, 'w')
        if _vigil_os.name == 'nt':  # Windows
            import msvcrt
            msvcrt.locking(_lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        else:  # Unix
            import fcntl
            fcntl.flock(_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_file.write(str(_vigil_os.getpid()))
        _lock_file.flush()
        logger.info("instance lock acquired (pid=%d)", _vigil_os.getpid())
    except (IOError, OSError):
        logger.error("Vigil is already running. Only one instance allowed.")
        _vigil_sys.exit(1)

    # 0. Recover from leftover WAL locks left by a previous unclean shutdown,
    # before aiosqlite opens its own connection in init_db().
    try:
        import sqlite3 as _sqlite3
        import os as _os
        _db_path = str(DB_PATH) if 'DB_PATH' in dir() else \
            _os.path.join(
                _os.environ.get('VLAW_DATA_DIR',
                    _os.path.join(_os.path.dirname(__file__),
                                  '..', 'data')),
                'vlaw.db'
            )
        _conn = _sqlite3.connect(_db_path, timeout=3)
        _conn.execute("PRAGMA journal_mode=DELETE")
        _conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        _conn.commit()
        _conn.close()
        del _conn, _sqlite3, _os, _db_path
    except Exception:
        pass  # Never block startup — let init_db() report errors

    # 1. DB + schema
    await init_db()
    logger.info("database initialized")

    # As early as possible after the schema exists, so the recorded
    # started_at isn't delayed by license checks, crash recovery replay,
    # etc. below -- that delay would otherwise show up as a few extra
    # seconds of "Vigil was not running" in the next export.
    from core.monitoring_coverage import start_run as _start_coverage_run
    await _start_coverage_run()

    # 2. Policy
    _ensure_default_policy()
    policy = load_policy()
    logger.info("policy loaded: %d keys", len(policy))

    # 3. License (offline, 14-day trial fallback)
    license_service = LicenseService()
    license_status = license_service.get_status()
    logger.info("license status: plan=%s valid=%s trial=%s", license_status.plan, license_status.valid, license_status.is_trial)
    _state["license_status"] = license_status

    attributor = Attributor()
    aggregator = Aggregator()

    # Crash recovery: replay any file events buffered in memory but not yet
    # flushed to SQLite when the process last died (see
    # Aggregator.buffer_file_event / _append_crash_recovery_line). Must run
    # after init_db() (above) but before start_writer(), and uses get_db()
    # directly rather than enqueue() since the writer task doesn't exist yet.
    replayed = await aggregator.replay_crash_recovery_log()
    if replayed:
        logger.info("crash recovery: replayed %d file events from a previous run", replayed)

    aggregator._writer_task = asyncio.create_task(
        aggregator.start_writer(), name="vigil_db_writer"
    )
    # start_writer() runs unsupervised otherwise -- nothing else awaits this
    # task or checks .done() on it, so if it ever dies (an exception escaping
    # somewhere other than the per-write try/except inside start_writer(),
    # e.g. a CancelledError landing mid coro_factory()), every future
    # Aggregator.enqueue() call hangs forever awaiting a future nothing will
    # ever resolve, with no trace in the log. This makes that loud instead.
    aggregator._writer_task.add_done_callback(
        lambda t: logger.error(f"writer task ended unexpectedly: {t.exception()}")
        if not t.cancelled() and t.exception() else None
    )
    baseline = Baseline()

    # Session recovery: a session whose process died before
    # close_idle_sessions closed it (self._active is in-memory only, so it
    # doesn't survive a restart) is left with ended_at NULL forever --
    # never rolled up, scored, or summarized -- unless recovered here.
    # Needs `baseline` (just constructed above, see recover_orphaned_
    # sessions' scoring pass), so this can't run any earlier in startup.
    # Wrapped so a recovery failure can never stop the backend from
    # starting -- recover_orphaned_sessions already isolates one bad
    # session from the rest, this is the outer belt-and-suspenders in
    # case something fails before that per-session isolation even begins
    # (e.g. the initial SELECT itself).
    try:
        recovered = await attributor.sessions.recover_orphaned_sessions(baseline)
        if recovered:
            logger.info("session recovery: closed %d orphaned session(s) from a previous run", recovered)
    except Exception:
        logger.exception("session recovery failed -- continuing startup without it")

    process_watcher = ProcessWatcher(attributor, aggregator)
    network_watcher = NetworkWatcher(attributor, aggregator)
    mcp_watcher = McpWatcher(attributor)

    _state["aggregator"] = aggregator
    _state["baseline"] = baseline

    # 4. File watcher (PollingObserver — Docker/Windows safe)
    watch_paths, red_line_non_recursive_dirs = build_watch_paths(policy)
    observer, file_handler = start_file_watcher(
        attributor, aggregator, watch_paths, red_line_non_recursive_dirs,
        process_watcher=process_watcher, network_watcher=network_watcher,
    )
    _state["observer"] = observer
    logger.info("file watcher started, watching %d paths", len(watch_paths) + len(red_line_non_recursive_dirs))

    # 5. APScheduler jobs
    # Several watchers dispatch onto the loop's *default* executor (not
    # their own dedicated ones) -- asyncio.to_thread always does, and
    # file_watcher.py's _find_owning_agent_pid explicitly passes
    # executor=None to run_in_executor. Python's own default size
    # (min(32, cpu_count+4)) can be exhausted by enough concurrent
    # to_thread dispatches (e.g. many agent-named PIDs at once on
    # ProcessWatcher's cold start), after which anything else waiting on
    # the default executor queues behind them. Raised here, once, before
    # any watcher starts making default-executor calls.
    loop = asyncio.get_running_loop()
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=50))

    logger.info("Pre-warming PowerShell subprocess cache...")
    try:
        proc = await asyncio.create_subprocess_exec(
            'powershell', '-NoProfile', '-NonInteractive', '-Command', 'exit',
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.wait(), timeout=30)
        logger.info("PowerShell pre-warm complete")
    except Exception as e:
        logger.warning("PowerShell pre-warm failed (non-fatal): %s", e)

    # max_instances=1 (APScheduler's own default, made explicit here) stops
    # a slow poll from piling up overlapping runs of itself; coalesce=True
    # collapses any runs missed while the loop was busy into a single catch-up
    # run instead of firing them back-to-back. Each watcher re-derives its own
    # "what's changed" state fresh from the OS every poll (see e.g.
    # ProcessWatcher._known_pids), so collapsing missed runs doesn't drop any
    # detection — there's no queued-event backlog to lose.
    scheduler = AsyncIOScheduler()

    # Staggered next_run_time (5s/15s/25s from startup) so the three
    # watchers' 30s intervals never re-align to fire in the same instant —
    # each watcher's own 25s asyncio.timeout can otherwise expire at the
    # same moment as the other two, all three subprocess scans/DB work
    # landing on the event loop together and visibly delaying unrelated
    # requests (e.g. /health) for several seconds. A 10s gap spreads that
    # load across the cycle instead of bursting it.
    # core/monitoring_coverage.py's heartbeat rides on this specific job's
    # 30s interval (see record_coverage_tick(), called from
    # ProcessWatcher.poll() itself) rather than a scheduler job of its
    # own. If this job is ever disabled the way network_watcher/
    # mcp_watcher below already have been, Monitoring coverage in the
    # export silently stops advancing along with it.
    _now = datetime.now(scheduler.timezone)
    scheduler.add_job(
        process_watcher.poll, "interval", seconds=30, id="process_watcher",
        max_instances=1, coalesce=True, replace_existing=True,
        next_run_time=_now + timedelta(seconds=5),
    )
    # NetworkWatcher disabled pending event-loop audit — resolution phase contains blocking I/O.
    # scheduler.add_job(
    #     network_watcher.poll, "interval", seconds=30, id="network_watcher",
    #     max_instances=1, coalesce=True, replace_existing=True,
    #     next_run_time=_now + timedelta(seconds=15),
    # )
    # McpWatcher disabled pending async subprocess refactor — WMI contention with ProcessWatcher.
    # scheduler.add_job(
    #     mcp_watcher.poll, "interval", seconds=30, id="mcp_watcher",
    #     max_instances=1, coalesce=True, replace_existing=True,
    #     next_run_time=_now + timedelta(seconds=25),
    # )
    scheduler.add_job(aggregator.flush_buffers, "interval", seconds=15, id="aggregator_flush", max_instances=1, coalesce=True)
    # Stage 1 burst+correlation (see watchers/file_watcher.py::check_burst) —
    # independent of any single file event's own pid-guess attribution.
    scheduler.add_job(file_handler.check_burst, "interval", seconds=30, id="file_burst_check", max_instances=1, coalesce=True)
    scheduler.add_job(_baseline_tick, "interval", hours=1, id="baseline_update", args=[baseline], max_instances=1, coalesce=True)
    scheduler.add_job(
        _seal_evidence_chain, "interval", seconds=15, id="evidence_chain_seal",
        max_instances=1, coalesce=True,
    )
    # SessionManager.close_idle_sessions disabled pending event-loop audit.
    # scheduler.add_job(
    #     attributor.sessions.close_idle_sessions,
    #     "interval",
    #     seconds=60,
    #     id="session_idle_check",
    #     args=[baseline],
    #     max_instances=1,
    #     coalesce=True,
    # )
    scheduler.start()
    _state["scheduler"] = scheduler
    logger.info("scheduler started")

    yield

    # shutdown
    scheduler.shutdown(wait=False)
    observer.stop()
    observer.join(timeout=5)
    await aggregator.stop_writer()
    from core.monitoring_coverage import mark_clean_shutdown as _mark_coverage_clean_shutdown
    await _mark_coverage_clean_shutdown()
    await close_db()
    try:
        _lock_file.close()
        _vigil_os.unlink(_lock_path)
    except Exception:
        pass
    logger.info("vlaw shutdown complete")


async def _baseline_tick(baseline: Baseline) -> None:
    """Hourly job: fold any sessions that have ended since the last tick
    into their agent's baseline."""
    db = await get_db()
    cur = await db.execute(
        "SELECT id FROM sessions WHERE ended_at IS NOT NULL AND anomaly_score = 0"
    )
    rows = await cur.fetchall()
    for row in rows:
        await baseline.update_from_session(row["id"])


async def _seal_evidence_chain() -> None:
    # seal_new_events() now opens its own dedicated connection internally
    # (see core/evidence_chain.py) rather than taking the shared get_db()
    # singleton -- no db handle needed here anymore.
    from core.evidence_chain import seal_new_events
    await seal_new_events()


app = FastAPI(title="Vigil", version=VERSION, lifespan=lifespan)

# Allowed browser Origins for state-changing requests. http://localhost:7422
# and http://127.0.0.1:7422 are the web UI served by this backend itself;
# http://localhost:5173 is the Vite dev server. No vscode-webview:// entry
# is needed: vigil-vscode has no webview, every backend call it makes runs
# in the extension host (a Node process), which sends no Origin header at
# all, same as the tray and the Claude Code MCP plugin.
_ALLOWED_ORIGINS = {
    "http://localhost:7422",
    "http://127.0.0.1:7422",
    "http://localhost:5173",
}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _host_header_hostname(host_header: str) -> str:
    """Strips the port (and, for an IPv6 literal, the brackets) off a Host
    header value, so "127.0.0.1:7422", "[::1]:7422", and "localhost" all
    compare correctly against the allowed hostnames below."""
    host = host_header.strip()
    if host.startswith("["):
        return host[1:host.index("]")] if "]" in host else host
    return host.split(":")[0]


@app.middleware("http")
async def _localhost_origin_guard(request: Request, call_next):
    """Defense in depth even though the server only binds 127.0.0.1 (see
    VLAW_HOST above): any web page open in the developer's browser can
    still send a body-less POST to http://localhost:7422/api/... with no
    CORS preflight, since a simple POST is never preflighted -- that would
    let a hostile page dismiss alerts or block/approve an agent on an
    evidence product with zero interaction from the user. Two checks:

    1. Host header must resolve to localhost/127.0.0.1/::1 -- blocks DNS
       rebinding (a page on attacker.example pointing attacker.example's
       own DNS record at 127.0.0.1, which a bind-address check alone can't
       catch, since the request still arrives on the loopback interface).
    2. For state-changing methods, an Origin header, if present, must be
       in the allowlist. Real clients (the tray, the VS Code extension
       host, the Claude Code MCP plugin) are Node/Python processes and
       send no Origin at all, so an absent Origin is allowed; a browser
       always sends one on a cross-origin request, so a present-but-
       disallowed Origin is rejected."""
    hostname = _host_header_hostname(request.headers.get("host", ""))
    if hostname not in ("localhost", "127.0.0.1", "::1"):
        return JSONResponse(status_code=403, content={"detail": "forbidden host"})

    if request.method in _STATE_CHANGING_METHODS:
        origin = request.headers.get("origin")
        if origin is not None and origin not in _ALLOWED_ORIGINS:
            return JSONResponse(status_code=403, content={"detail": "forbidden origin"})

    return await call_next(request)


# Unprefixed registration exists only for dev mode: the frontend always
# calls /api/* (see frontend/src/api.js's BASE), but when it's run via
# `npm run dev`, Vite's own dev server proxies /api/* to this backend and
# strips the prefix before forwarding (see frontend/vite.config.js's
# rewrite), so the backend receives these requests unprefixed in that one
# workflow. The frozen build never has a Vite dev server in front of it, so
# this registration served no purpose there -- and was actively harmful,
# since several of these routers' own paths (/alerts, /agents, /incidents)
# are also names of frontend-meaningful screens: an unprefixed GET to one
# of them returned real API JSON instead of falling through to the SPA
# catch-all (spa_fallback below), surprising anyone who tried e.g. /alerts
# directly expecting the app shell.
if not getattr(sys, "frozen", False):
    app.include_router(events.router)
    app.include_router(agents.router)
    app.include_router(alerts.router)
    app.include_router(export.router)
    app.include_router(digest_api.router)
    app.include_router(sessions.router)
    app.include_router(config_api.router)
    app.include_router(analytics_api.router)
    app.include_router(evidence.router)
    app.include_router(chain_routes.router)

# mcp_routes/platform_routes/git_routes have no /api-prefixed twin at all
# (see below) -- the VS Code extension calls these directly, unprefixed,
# in production too (vigil-vscode/src/api.ts calls {baseUrl}/mcp/call), so
# unlike the routers above, this registration is load-bearing in the
# frozen build and must stay unconditional.
app.include_router(mcp_routes.router)
app.include_router(platform_routes.router)
app.include_router(git_routes.router)

# The built frontend calls /api/* (see frontend/src/api.js). In dev, Vite's
# proxy strips that prefix before forwarding to the backend; in production
# there's no dev server, so the same routers are mounted again under /api.
app.include_router(events.router, prefix="/api")
app.include_router(agents.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(export.router, prefix="/api")
app.include_router(digest_api.router, prefix="/api")
app.include_router(sessions.router, prefix="/api")
app.include_router(config_api.router, prefix="/api")
app.include_router(analytics_api.router, prefix="/api")
app.include_router(evidence.router, prefix="/api")
app.include_router(chain_routes.router, prefix="/api")


_STATS_CACHE_TTL_SECONDS = 2.0
_stats_cache = {"data": None, "computed_at": 0.0}


@app.get("/stats")
@app.get("/api/stats")
async def get_stats():
    """Polled every 3s by App.jsx on every page -- it's part of the app
    shell, never unmounted. Measured directly on the live machine: 4.3s,
    9.1s, 5.9s per call, which at ~0.82-0.94 CPU cores with the dashboard
    open (vs 0.01 idle) was clearly the dominant cost.

    This used to run 13 sequential queries on the shared get_db()
    singleton, most wrapping created_at in date(...) in the WHERE clause
    -- date(created_at) = date('now') -- which defeats any index on that
    column (EXPLAIN QUERY PLAN confirmed SCAN, not SEARCH, even where an
    index existed). Measured on a copy of the live DB (~15k events, ~3k
    alerts): all 13 queries combined cost only ~7.5ms there, ruling out
    raw query cost as the cause of the multi-second latency at today's
    scale. The real cause is connection contention: get_db() is the one
    shared, single-writer-thread connection that ProcessWatcher, the
    file watcher, Aggregator.flush_buffers, and _seal_evidence_chain all
    write through -- the same class of hazard already fixed for
    seal_new_events()/verify_chain() in core/evidence_chain.py, just
    never applied here even though this is the highest-frequency reader
    in the app.

    Fixed four ways:
    1. get_read_db() instead of get_db() -- a dedicated connection that
       never queues behind the shared writer thread.
    2. Every date(created_at) = date('now') replaced with a
       created_at >= ? AND created_at < ? range against UTC day
       boundaries computed in Python, so the planner can do an actual
       index range SEARCH (idx_events_created, idx_alerts_created,
       idx_sessions_started -- the latter two added alongside this fix).
    3. 13 round-trips consolidated into 6 queries via conditional
       SUM(CASE WHEN ...), each still restricted to created_at >=
       yesterday's start so the index prunes everything older than that
       regardless of how large events/alerts grow.
    4. A short in-process cache (TTL above) so concurrent pollers
       (multiple tabs, or Sidebar/App.jsx polling close together) don't
       each pay even the now-cheap query cost.

    Still protects against the table growing: cost here scales with
    "rows from yesterday onward", not total table size, since every
    multi-row query is now WHERE-bounded on the indexed created_at
    column rather than scanning everything."""
    now_ts = time.monotonic()
    if _stats_cache["data"] is not None and now_ts - _stats_cache["computed_at"] < _STATS_CACHE_TTL_SECONDS:
        return _stats_cache["data"]

    db = await get_read_db()
    try:
        now = datetime.now(timezone.utc)
        today_start = now.strftime("%Y-%m-%d 00:00:00")
        tomorrow_start = (now + timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
        yesterday_start = (now - timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")

        cur = await db.execute("SELECT COUNT(*) c FROM agents WHERE approved = 1")
        active_agents = (await cur.fetchone())["c"]

        cur = await db.execute(
            """
            SELECT
                SUM(CASE WHEN created_at >= ? AND created_at < ? THEN 1 ELSE 0 END) AS events_today,
                SUM(CASE WHEN created_at >= ? AND created_at < ? THEN 1 ELSE 0 END) AS events_yesterday,
                SUM(CASE WHEN created_at >= ? AND created_at < ? AND event_type = 'net_connect'
                    THEN COALESCE(data_volume_bytes, 0) ELSE 0 END) AS net_bytes_today,
                SUM(CASE WHEN created_at >= ? AND created_at < ? AND event_type = 'net_connect'
                    THEN COALESCE(data_volume_bytes, 0) ELSE 0 END) AS net_bytes_yesterday,
                SUM(CASE WHEN created_at >= ? AND created_at < ? AND event_type = 'cred_access'
                    THEN 1 ELSE 0 END) AS cred_accesses_today,
                SUM(CASE WHEN created_at >= ? AND created_at < ? AND event_type = 'cred_access'
                    THEN 1 ELSE 0 END) AS cred_accesses_yesterday
            FROM events
            WHERE created_at >= ?
            """,
            (
                today_start, tomorrow_start,
                yesterday_start, today_start,
                today_start, tomorrow_start,
                yesterday_start, today_start,
                today_start, tomorrow_start,
                yesterday_start, today_start,
                yesterday_start,
            ),
        )
        events_row = await cur.fetchone()
        events_today = events_row["events_today"] or 0
        events_yesterday = events_row["events_yesterday"] or 0
        net_bytes_today = events_row["net_bytes_today"] or 0
        net_bytes_yesterday = events_row["net_bytes_yesterday"] or 0
        cred_accesses_today = events_row["cred_accesses_today"] or 0
        cred_accesses_yesterday = events_row["cred_accesses_yesterday"] or 0

        cur = await db.execute("SELECT COUNT(*) c FROM alerts WHERE status = 'open'")
        alerts_open = (await cur.fetchone())["c"]

        # Single definition of "needs review", used everywhere a review
        # count is shown (tray tooltip, Status page, Incidents sidebar
        # badge): open alerts at severity high or critical. Pending-agent
        # approval is a separate concept (see api/agents.py) and is never
        # folded into this number.
        cur = await db.execute(
            "SELECT COUNT(*) c FROM alerts WHERE status = 'open' AND severity IN ('high', 'critical')"
        )
        needs_review = (await cur.fetchone())["c"]

        # checkpoint_activity (RL3's normal-/rewind tier — see core/red_lines.py)
        # is expected, frequent, benign background noise, not a "meaningful
        # alert" in Sprint A's sense — excluded from the noise-reduction
        # numerator below so it doesn't inflate the count of alerts that
        # actually warrant a human's attention.
        cur = await db.execute(
            """
            SELECT
                SUM(CASE WHEN status = 'open' AND created_at >= ? AND created_at < ?
                    THEN 1 ELSE 0 END) AS alerts_open_yesterday,
                SUM(CASE WHEN created_at >= ? AND created_at < ? THEN 1 ELSE 0 END) AS alerts_today,
                SUM(CASE WHEN created_at >= ? AND created_at < ? AND rule_type != 'checkpoint_activity'
                    THEN 1 ELSE 0 END) AS meaningful_alerts_today
            FROM alerts
            WHERE created_at >= ?
            """,
            (
                yesterday_start, today_start,
                today_start, tomorrow_start,
                today_start, tomorrow_start,
                yesterday_start,
            ),
        )
        alerts_row = await cur.fetchone()
        alerts_open_yesterday = alerts_row["alerts_open_yesterday"] or 0
        alerts_today = alerts_row["alerts_today"] or 0
        meaningful_alerts_today = alerts_row["meaningful_alerts_today"] or 0

        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE started_at >= ? AND started_at < ?",
            (today_start, tomorrow_start),
        )
        sessions_today = (await cur.fetchone())["c"]

        cur = await db.execute("SELECT value FROM stats_kv WHERE key = 'suppressed_alerts'")
        row = await cur.fetchone()
        suppressed_alerts = row["value"] if row else 0
    finally:
        await db.close()

    # Signal-over-noise: how much raw activity got compressed down to
    # alerts actually worth a human's attention today.
    noise_reduction_ratio = round(meaningful_alerts_today / events_today, 4) if events_today else 0.0

    result = {
        "version": VERSION,
        "active_agents": active_agents,
        "events_today": events_today,
        "events_yesterday": events_yesterday,
        "alerts_open": alerts_open,
        "alerts_open_yesterday": alerts_open_yesterday,
        "needs_review": needs_review,
        "net_egress_mb_today": round(net_bytes_today / (1024 * 1024), 3),
        "net_egress_mb_yesterday": round(net_bytes_yesterday / (1024 * 1024), 3),
        "cred_accesses_today": cred_accesses_today,
        "cred_accesses_yesterday": cred_accesses_yesterday,
        "sessions_today": sessions_today,
        "alerts_today": alerts_today,
        "meaningful_alerts_today": meaningful_alerts_today,
        "noise_reduction_ratio": noise_reduction_ratio,
        "suppressed_alerts": suppressed_alerts,
    }
    _stats_cache["data"] = result
    _stats_cache["computed_at"] = now_ts
    return result


@app.get("/health")
@app.get("/api/health")
async def health():
    license_status = _state.get("license_status")
    observer = _state.get("observer")

    db = await get_db()
    cur = await db.execute("SELECT COUNT(*) c FROM agents WHERE pid IS NOT NULL")
    agents_watching = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM agents WHERE julianday('now') - julianday(first_seen) >= 14"
    )
    baseline_active = (await cur.fetchone())["c"] > 0

    return {
        "status": "ok",
        "version": VERSION,
        "license_status": {
            "plan": license_status.plan if license_status else "unknown",
            "valid": license_status.valid if license_status else False,
            "is_trial": license_status.is_trial if license_status else True,
            "expired": license_status.expired if license_status else False,
        },
        "baseline_active": baseline_active,
        "agents_watching": agents_watching,
        "file_watcher_alive": observer.is_alive() if observer else False,
    }


@app.get("/insights")
@app.get("/api/insights")
async def insights():
    return await get_insights()


@app.get("/config-audit")
@app.get("/api/config-audit")
async def config_audit():
    """Audits the user's own native Claude Code config (permissions.deny
    in settings.json) against core.config_auditor.RECOMMENDED_DENY_PATTERNS
    — read-only, never writes to the user's config. Runs synchronously
    against local disk reads (no DB/network), cheap enough to call on
    every request rather than caching."""
    if CORE_ONLY:
        return {"disabled": True, "reason": "core-only mode"}
    return audit_all_configs(str(SESSION_LAUNCH_DIR))


@app.get("/anomalies/recent")
async def anomalies_recent():
    db = await get_db()
    cur = await db.execute(
        """
        SELECT al.*, a.name as agent_name
        FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        WHERE al.rule_type IN ('volumetric_threshold', 'time_anomaly', 'ratio_anomaly', 'unknown_destination', 'rolling_anomaly')
          AND al.created_at > datetime('now', '-7 days')
        ORDER BY al.created_at DESC
        LIMIT 20
        """
    )
    rows = await cur.fetchall()
    return [dict(r) for r in rows]


# Frontend (built React app) — installer places it as a sibling of the
# backend exe: {app}\frontend\index.html, {app}\frontend\assets\*. Frozen
# BASE_DIR is the per-user data dir (%LOCALAPPDATA%\V-LAW), not the install
# dir, so the frozen case resolves from sys.executable's directory instead.
# Mounted last so it never shadows the API routes registered above.
if getattr(sys, "frozen", False):
    FRONTEND_DIR = os.path.normpath(os.path.join(os.path.dirname(sys.executable), "..", "frontend"))
else:
    FRONTEND_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "dist"))

if os.path.isdir(FRONTEND_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="frontend-assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        # Without this check, a typo'd or nonexistent /api/* path (nothing
        # matched above -- every real API route is already registered
        # earlier and would never reach here) falls through to this
        # catch-all and gets served index.html with a 200, not a 404. The
        # frontend's own api.js always calls through BASE = '/api', so a
        # bad call there should fail loudly, not come back as HTML that
        # res.json() then throws a cryptic SyntaxError trying to parse.
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        index = os.path.join(FRONTEND_DIR, "index.html")
        return FileResponse(index)
else:
    logger.warning("frontend not found at %s — web UI will not be served", FRONTEND_DIR)


if __name__ == "__main__":
    import uvicorn

    # The API has no auth and includes mutating routes (approve/block an
    # agent, resolve/dismiss an alert), so it must not be reachable from
    # the LAN. 127.0.0.1 is the correct default for every real client:
    # the tray, the VS Code extension, and the Claude Code MCP plugin all
    # already target 127.0.0.1/localhost explicitly (checked before this
    # change). VLAW_HOST is an escape hatch for a deployment that needs a
    # different interface, not something to be set by default.
    HOST = os.environ.get("VLAW_HOST", "127.0.0.1")

    # Pass the app object directly rather than the "main:app" string form:
    # the string form makes uvicorn re-import "main" by module name, which
    # doesn't resolve inside a frozen PyInstaller executable.
    uvicorn.run(app, host=HOST, port=PORT, reload=False)
