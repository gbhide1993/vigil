"""Session lifecycle. One row per agent run: opened on the agent's first
attributed activity, closed after a period of inactivity. Session stat
columns (file_reads, file_writes, ...) are rolled up from the events
table when a session closes, then handed to baseline.update_from_session()."""

import uuid
from datetime import datetime, timezone

from db.database import get_db

SESSION_IDLE_TIMEOUT_SECONDS = 300  # close a session after 5 minutes of no activity


class SessionManager:
    def __init__(self):
        # agent_id -> {"session_id": str, "last_activity": datetime}
        self._active: dict[int, dict] = {}

    async def touch(self, agent_id: int) -> str:
        """Record activity for an agent, opening a new session if none is
        active. Returns the current session_id for this agent."""
        db = await get_db()
        now = datetime.now(timezone.utc)

        active = self._active.get(agent_id)
        if active is not None:
            active["last_activity"] = now
            return active["session_id"]

        session_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (session_id, agent_id),
        )
        await db.execute(
            "UPDATE agents SET session_count = session_count + 1 WHERE id = ?",
            (agent_id,),
        )
        await db.commit()

        self._active[agent_id] = {"session_id": session_id, "last_activity": now}
        return session_id

    async def close_idle_sessions(self, baseline) -> list[str]:
        """Called periodically by the scheduler. Closes any session whose
        agent has been inactive past the idle timeout, rolls up its stat
        columns from the events table, and feeds it to baseline. Returns
        the list of closed session_ids."""
        db = await get_db()
        now = datetime.now(timezone.utc)
        closed: list[str] = []

        idle_agent_ids = [
            agent_id
            for agent_id, info in self._active.items()
            if (now - info["last_activity"]).total_seconds() >= SESSION_IDLE_TIMEOUT_SECONDS
        ]

        for agent_id in idle_agent_ids:
            info = self._active.pop(agent_id)
            session_id = info["session_id"]

            await self._roll_up_session_stats(db, session_id, agent_id)
            await db.execute(
                "UPDATE sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?",
                (session_id,),
            )
            await db.commit()

            await baseline.update_from_session(session_id)
            closed.append(session_id)

        return closed

    async def _roll_up_session_stats(self, db, session_id: str, agent_id: int) -> None:
        cur = await db.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN event_type = 'file_read' THEN file_count ELSE 0 END), 0) as file_reads,
                COALESCE(SUM(CASE WHEN event_type = 'file_write' THEN file_count ELSE 0 END), 0) as file_writes,
                COALESCE(SUM(CASE WHEN event_type = 'net_connect' THEN data_volume_bytes ELSE 0 END), 0) as net_egress_bytes,
                COALESCE(SUM(CASE WHEN event_type = 'proc_spawn' THEN 1 ELSE 0 END), 0) as proc_spawns,
                COALESCE(SUM(CASE WHEN event_type = 'cred_access' THEN 1 ELSE 0 END), 0) as cred_accesses,
                COALESCE(SUM(CASE WHEN event_type = 'mcp_connect' THEN 1 ELSE 0 END), 0) as mcp_connects
            FROM events
            WHERE session_id = ? AND agent_id = ?
            """,
            (session_id, agent_id),
        )
        stats = await cur.fetchone()

        cur = await db.execute(
            "SELECT COUNT(*) c FROM alerts WHERE agent_id = ? AND event_id IN (SELECT id FROM events WHERE session_id = ?)",
            (agent_id, session_id),
        )
        alert_count = (await cur.fetchone())["c"]

        await db.execute(
            """
            UPDATE sessions SET
                file_reads = ?, file_writes = ?, net_egress_bytes = ?,
                proc_spawns = ?, cred_accesses = ?, mcp_connects = ?, alert_count = ?
            WHERE id = ?
            """,
            (
                stats["file_reads"], stats["file_writes"], stats["net_egress_bytes"],
                stats["proc_spawns"], stats["cred_accesses"], stats["mcp_connects"],
                alert_count, session_id,
            ),
        )
