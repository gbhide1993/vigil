"""Maps OS-level signals (PID, network destination) to the agent that
caused them. This is the core of V-LAW's per-agent attribution."""

import json
import time

import psutil

from core.alerter import Alerter
from core.sessions import SessionManager
from db.database import get_db

KNOWN_AGENTS = {
    "cursor":        ["Cursor", "cursor_ui", "cursor-server"],
    "claude_code":   ["claude", "claude-code", "claude_code"],
    "copilot":       ["GitHub.Copilot", "copilot-agent"],
    "agentforce":    ["salesforce-agent", "agentforce"],
}

# Network destination -> agent mapping fallback
KNOWN_DESTINATIONS = {
    "api.anthropic.com":   "claude_code",
    "api.openai.com":      "cursor",
    "api.github.com":      "copilot",
    "api.salesforce.com":  "agentforce",
}

# A PID's parent chain doesn't change between polls unless the process
# itself changes (i.e. the PID is reused for a new process) — walking up
# to 10 parent levels via psutil.Process().parent() on every poll for a
# still-running PID is wasted work, and was the dominant remaining cost
# once ProcessWatcher.poll/NetworkWatcher.poll stopped blocking the event
# loop directly (~4s for ~109 connections, measured on a real dev machine).
# TTL is a memory-growth safeguard for dead PIDs, not a correctness window
# — process identity itself doesn't expire. Same TTL + size-cap cleanup
# shape as core.red_lines._purge_stale_pending_config_writes.
_agent_attribution_cache: dict[int, tuple[str | None, float]] = {}
ATTRIBUTION_CACHE_TTL_SECONDS = 30
ATTRIBUTION_CACHE_MAX_ENTRIES = 2000


def _purge_stale_attribution_cache() -> None:
    """TTL + size-cap cleanup for _agent_attribution_cache. Called on every
    get_agent_for_pid so the dict never grows unbounded over a long-running
    session (many short-lived PIDs) without needing its own scheduler job."""
    now = time.time()
    stale_pids = [
        pid for pid, (_, cached_at) in list(_agent_attribution_cache.items())
        if now - cached_at > ATTRIBUTION_CACHE_TTL_SECONDS
    ]
    for pid in stale_pids:
        _agent_attribution_cache.pop(pid, None)

    if len(_agent_attribution_cache) > ATTRIBUTION_CACHE_MAX_ENTRIES:
        oldest_first = sorted(list(_agent_attribution_cache.items()), key=lambda kv: kv[1][1])
        overflow = len(_agent_attribution_cache) - ATTRIBUTION_CACHE_MAX_ENTRIES
        for pid, _ in oldest_first[:overflow]:
            _agent_attribution_cache.pop(pid, None)


class Attributor:
    def __init__(self):
        self.alerter = Alerter()
        self.sessions = SessionManager()

    def get_agent_for_pid(self, pid: int) -> str | None:
        """Match a PID to a known agent by process name, walking up the
        parent chain if the direct process isn't a known agent binary.
        Cached per-PID (see _agent_attribution_cache above) since a PID's
        parent chain and name are immutable for the process's lifetime —
        only the TTL bounds cache memory for PIDs that have since exited,
        it doesn't re-check anything for a still-running PID."""
        _purge_stale_attribution_cache()

        now = time.time()
        cached = _agent_attribution_cache.get(pid)
        if cached is not None:
            agent, cached_at = cached
            if now - cached_at < ATTRIBUTION_CACHE_TTL_SECONDS:
                return agent

        agent = self._walk_parent_chain(pid)
        _agent_attribution_cache[pid] = (agent, now)
        return agent

    def _walk_parent_chain(self, pid: int) -> str | None:
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        current = proc
        depth = 0
        while current is not None and depth < 10:
            name = current.name()
            for agent_key, process_names in KNOWN_AGENTS.items():
                if any(pn.lower() in name.lower() for pn in process_names):
                    return agent_key
            try:
                current = current.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                current = None
            depth += 1

        return None

    def get_agent_for_destination(self, dest: str) -> str | None:
        """Match a network destination host to a known agent."""
        return KNOWN_DESTINATIONS.get(dest)

    async def get_or_create_agent(self, name: str, pid: int | None = None) -> int:
        """Return agent_id from DB, creating the row if this is the first
        time we've seen this agent. New agents default to approved=0
        (pending) and fire a CRITICAL alert if not on the approved list."""
        db = await get_db()

        cur = await db.execute("SELECT id FROM agents WHERE name = ?", (name,))
        row = await cur.fetchone()

        if row is not None:
            await db.execute(
                "UPDATE agents SET last_seen = CURRENT_TIMESTAMP, pid = ? WHERE id = ?",
                (pid, row["id"]),
            )
            await db.commit()
            return row["id"]

        is_approved = await self._is_approved_agent(db, name)

        cur = await db.execute(
            """
            INSERT INTO agents (name, process_name, pid, approved)
            VALUES (?, ?, ?, ?)
            """,
            (name, name, pid, 1 if is_approved else 0),
        )
        await db.commit()
        agent_id = cur.lastrowid

        if not is_approved:
            await self._fire_unapproved_agent_alert(db, agent_id, name, pid)

        return agent_id

    async def _is_approved_agent(self, db, name: str) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'approved_agents'"
        )
        row = await cur.fetchone()
        if row is None:
            return False
        approved = json.loads(row["policy_value"])
        return name in approved

    async def _fire_unapproved_agent_alert(self, db, agent_id: int, name: str, pid: int | None = None) -> None:
        cur = await db.execute(
            "SELECT id FROM alerts WHERE agent_id = ? AND severity = 'critical' AND status = 'open'",
            (agent_id,),
        )
        if await cur.fetchone() is not None:
            return

        await self.alerter.fire_alert(
            agent_id,
            "critical",
            title=f"Unapproved agent detected: {name}",
            description=f"{name} (PID {pid}) is running and accessing your file system. "
            "This agent is not on the approved list. Review and approve or block below.",
            reason="unapproved_agent",
            extra_detail={"name": name},
        )
