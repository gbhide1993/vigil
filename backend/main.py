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

import logging
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI

from api import agents, alerts, digest_api, events, export, sessions
from config.policy import load_policy
from core.aggregator import Aggregator
from core.attributor import Attributor
from core.baseline import Baseline
from core.insights import get_insights
from db.database import close_db, get_db, init_db
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

VERSION = "0.1.0"
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
    # 1. DB + schema
    await init_db()
    logger.info("database initialized")

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
    baseline = Baseline()
    process_watcher = ProcessWatcher(attributor)
    network_watcher = NetworkWatcher(attributor, aggregator)
    mcp_watcher = McpWatcher(attributor)

    _state["aggregator"] = aggregator
    _state["baseline"] = baseline

    # 4. File watcher (PollingObserver — Docker/Windows safe)
    # VLAW_HOST_ROOT is set to /host in docker-compose.yml, where the
    # read-only host filesystem is mounted. Policy paths are defined from
    # the host's perspective (e.g. /src), so they need that prefix to
    # resolve inside the container. Empty by default for native (non-Docker)
    # runs, where policy paths already resolve directly.
    host_root = os.environ.get("VLAW_HOST_ROOT", "")
    scope_dirs = [host_root + p for p in policy.get("scope_directories", [])]
    credential_paths = policy.get("credential_paths", [])
    credential_dirs = [
        p for p in credential_paths
        if p.endswith("/") or p.endswith("\\") or p.startswith("~")
    ]
    # Red Line rules 1 and 3 (SSH directory access, Claude hidden cache
    # writes) must fire regardless of policy configuration, so their
    # directories are always watched — independent of whatever the user
    # has set in credential_paths/scope_directories.
    red_line_dirs = [host_root + os.path.expanduser("~/.ssh/"), host_root + os.path.expanduser("~/.claude/file-history/")]
    watch_paths = scope_dirs + [host_root + p for p in credential_dirs] + red_line_dirs
    observer = start_file_watcher(attributor, aggregator, watch_paths)
    _state["observer"] = observer
    logger.info("file watcher started, watching %d paths", len(watch_paths))

    # 5. APScheduler jobs
    scheduler = AsyncIOScheduler()
    scheduler.add_job(process_watcher.poll, "interval", seconds=3, id="process_watcher")
    scheduler.add_job(network_watcher.poll, "interval", seconds=5, id="network_watcher")
    scheduler.add_job(mcp_watcher.poll, "interval", seconds=5, id="mcp_watcher")
    scheduler.add_job(aggregator.flush_buffers, "interval", seconds=5, id="aggregator_flush")
    scheduler.add_job(_baseline_tick, "interval", hours=1, id="baseline_update", args=[baseline])
    scheduler.add_job(
        attributor.sessions.close_idle_sessions,
        "interval",
        seconds=60,
        id="session_idle_check",
        args=[baseline],
    )
    scheduler.start()
    _state["scheduler"] = scheduler
    logger.info("scheduler started")

    yield

    # shutdown
    scheduler.shutdown(wait=False)
    observer.stop()
    observer.join(timeout=5)
    await close_db()
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


app = FastAPI(title="V-LAW", version=VERSION, lifespan=lifespan)

app.include_router(events.router)
app.include_router(agents.router)
app.include_router(alerts.router)
app.include_router(export.router)
app.include_router(digest_api.router)
app.include_router(sessions.router)


@app.get("/stats")
async def get_stats():
    db = await get_db()

    cur = await db.execute("SELECT COUNT(*) c FROM agents WHERE approved = 1")
    active_agents = (await cur.fetchone())["c"]

    cur = await db.execute("SELECT COUNT(*) c FROM events WHERE date(created_at) = date('now')")
    events_today = (await cur.fetchone())["c"]

    cur = await db.execute("SELECT COUNT(*) c FROM alerts WHERE status = 'open'")
    alerts_open = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COALESCE(SUM(data_volume_bytes), 0) v FROM events WHERE event_type = 'net_connect' AND date(created_at) = date('now')"
    )
    net_bytes_today = (await cur.fetchone())["v"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE event_type = 'cred_access' AND date(created_at) = date('now')"
    )
    cred_accesses_today = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM sessions WHERE date(started_at) = date('now')"
    )
    sessions_today = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE date(created_at) = date('now')"
    )
    alerts_today = (await cur.fetchone())["c"]

    cur = await db.execute("SELECT value FROM stats_kv WHERE key = 'suppressed_alerts'")
    row = await cur.fetchone()
    suppressed_alerts = row["value"] if row else 0

    # Signal-over-noise: how much raw activity got compressed down to
    # alerts actually worth a human's attention today.
    noise_reduction_ratio = round(alerts_today / events_today, 4) if events_today else 0.0

    return {
        "active_agents": active_agents,
        "events_today": events_today,
        "alerts_open": alerts_open,
        "net_egress_mb_today": round(net_bytes_today / (1024 * 1024), 3),
        "cred_accesses_today": cred_accesses_today,
        "sessions_today": sessions_today,
        "alerts_today": alerts_today,
        "noise_reduction_ratio": noise_reduction_ratio,
        "suppressed_alerts": suppressed_alerts,
    }


@app.get("/health")
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
async def insights():
    return await get_insights()


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


if __name__ == "__main__":
    import uvicorn

    # Pass the app object directly rather than the "main:app" string form:
    # the string form makes uvicorn re-import "main" by module name, which
    # doesn't resolve inside a frozen PyInstaller executable.
    uvicorn.run(app, host="0.0.0.0", port=PORT, reload=False)
