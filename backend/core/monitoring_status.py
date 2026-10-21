"""Which optional monitors (network, MCP connections) are actually running,
read from live state.

The answer comes from the scheduler (main.py binds it once the jobs are
registered and started), not from a constant: if the network watcher's job
is added back to the scheduler, network monitoring reads "on" everywhere
(health endpoint, report coverage section, report notes) with no other
change. Before the scheduler is bound (tests, early startup) everything
reads "off", which is the safe, honest default.
"""

NETWORK_WATCHER_JOB_ID = "network_watcher"
MCP_WATCHER_JOB_ID = "mcp_watcher"

_scheduler = None


def bind_scheduler(scheduler) -> None:
    global _scheduler
    _scheduler = scheduler


def _job_running(job_id: str) -> bool:
    scheduler = _scheduler
    if scheduler is None:
        return False
    try:
        return bool(scheduler.running) and scheduler.get_job(job_id) is not None
    except Exception:
        return False


def network_monitoring() -> str:
    """"on" if the network watcher's job is registered in a running
    scheduler, else "off"."""
    return "on" if _job_running(NETWORK_WATCHER_JOB_ID) else "off"


def mcp_monitoring() -> str:
    """"on" if the MCP watcher's job is registered in a running scheduler,
    else "off". (MCP *connections* are what this covers; changes to MCP
    config files are ordinary file events and do not depend on it.)"""
    return "on" if _job_running(MCP_WATCHER_JOB_ID) else "off"


# Which file-watching tier came up: "etw" (kernel tracing, every change made by a recognised agent anywhere),
# "native" (real-time folder observer, only the watched folders) or "polling" (folder polling, only the watched
# folders). Set from what start_file_watcher actually returned; "polling" is the safe default.
FILE_WATCHER_TIERS = ("etw", "native", "polling")
_file_tier = "polling"
_etw_reason: str | None = "kernel tracing has not been started"


def set_file_watcher_tier(tier: str) -> None:
    """Anything that is not "etw" or "native" (including the old "folders") reads as "polling"."""
    global _file_tier
    _file_tier = tier if tier in FILE_WATCHER_TIERS else "polling"
    if _file_tier == "etw":
        set_etw_unavailable_reason(None)


def file_watcher_tier() -> str:
    return _file_tier


def set_etw_unavailable_reason(reason: str | None) -> None:
    """None means ETW is running; otherwise the plain-English reason it is not."""
    global _etw_reason
    _etw_reason = reason


def etw_available() -> bool:
    return _file_tier == "etw"


def etw_unavailable_reason() -> str | None:
    """Why kernel tracing is not running, or None when it is."""
    return None if etw_available() else (_etw_reason or "kernel tracing did not start")


def describe_etw_failure(error: str | None) -> str:
    """Turns an ETW start error into a short sentence for /health and the tray tooltip."""
    text = (error or "").strip()
    low = text.lower()
    if "access is denied" in low or "administrator" in low or "privilege" in low or "elevat" in low:
        return "kernel tracing needs administrator"
    if not text:
        return "kernel tracing did not start"
    return f"kernel tracing could not start ({text[:80]})"
