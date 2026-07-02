"""Maps OS-level signals (PID, network destination) to the agent that
caused them. This is the core of V-LAW's per-agent attribution."""

import json

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


class Attributor:
    def __init__(self):
        self.alerter = Alerter()
        self.sessions = SessionManager()

    def get_agent_for_pid(self, pid: int) -> str | None:
        """Match a PID to a known agent by process name, walking up the
        parent chain if the direct process isn't a known agent binary."""
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
            await self._fire_unapproved_agent_alert(db, agent_id, name)

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

    async def _fire_unapproved_agent_alert(self, db, agent_id: int, name: str) -> None:
        await self.alerter.fire_alert(
            agent_id,
            "critical",
            title=f"Unapproved agent detected: {name}",
            description=f"Agent '{name}' was detected running on this machine but is "
            "not in the approved_agents policy list.",
            reason="unapproved_agent",
            extra_detail={"name": name},
        )
