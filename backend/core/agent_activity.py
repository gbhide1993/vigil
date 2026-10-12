"""What "running", "open (idle)" and "active" mean for an agent.

- running: a process of that agent exists right now (a desktop app, an editor extension's
  background helper, an agent CLI, or one of their children). This comes from the process
  watcher's latest scan (watchers/process_watcher.py, `running_agents`).
- active: real activity in the last ACTIVITY_WINDOW_SECONDS (5 minutes), recorded as events
  attributed to the agent: a file change, a network or MCP event, a credential access, or a
  new tool or shell process started under one of the agent's processes. The agent's own
  long-lived helper processes, and processes found already running when Vigil started, do not
  count, and neither does the mere existence of an open session.
- open (idle): running, but not active.
- not running: no process of that agent exists.

The tray tooltip, the sidebar and /api/agents all use these definitions.
"""

from datetime import datetime, timedelta, timezone

ACTIVITY_WINDOW_SECONDS = 300

ACTIVE = "active"
OPEN_IDLE = "open_idle"
NOT_RUNNING = "not_running"

# Events that are real activity. A proc_spawn counts only when it is a new tool or shell
# process under an agent (detail.activity_spawn) and not the marker for a process that was
# already running when Vigil started (detail.already_running).
_ACTIVITY_SQL = """
    SELECT agent_id, MAX(created_at) AS last_activity
    FROM events
    WHERE created_at >= ?
      AND agent_id IS NOT NULL
      AND (
        event_type != 'proc_spawn'
        OR (COALESCE(json_extract(detail, '$.activity_spawn'), 0) = 1
            AND COALESCE(json_extract(detail, '$.already_running'), 0) = 0)
      )
    GROUP BY agent_id
"""


def _cutoff(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return (now - timedelta(seconds=ACTIVITY_WINDOW_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")


async def recent_activity(db, now: datetime | None = None) -> dict[int, str]:
    """{agent_id: time of the latest real activity} for agents active in the window."""
    cur = await db.execute(_ACTIVITY_SQL, (_cutoff(now),))
    return {row["agent_id"]: row["last_activity"] for row in await cur.fetchall()}


def classify(running: bool, last_activity: str | None) -> str:
    if last_activity:
        return ACTIVE
    return OPEN_IDLE if running else NOT_RUNNING


def running_pids(process_watcher, agent_name: str) -> list[int]:
    """pids of the agent's processes in the latest scan (empty when no watcher is available)."""
    if process_watcher is None:
        return []
    return list(getattr(process_watcher, "running_agents", {}).get(agent_name, []))
