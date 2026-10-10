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
