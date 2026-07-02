"""Detects MCP server connections. MCP servers typically listen on
localhost ports 8000-9000 or communicate over stdio, so detection is
best-effort: localhost connections in that port range, plus processes
whose command line mentions "mcp"."""

import json

import psutil

from core.alerter import Alerter
from core.attributor import Attributor
from db.database import get_db

POLL_INTERVAL_SECONDS = 5

MCP_PORT_RANGE = range(8000, 9001)
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost"}


def _is_mcp_process(cmdline: str, name: str) -> bool:
    lowered = (cmdline + " " + name).lower()
    return "mcp" in lowered


class McpWatcher:
    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self.alerter = Alerter()
        self._seen_connections: set[tuple] = set()

    async def poll(self) -> None:
        db = await get_db()
        current_keys: set[tuple] = set()

        # 1. Localhost connections in the MCP port range
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            connections = []

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or conn.raddr is None:
                continue
            if conn.raddr.ip not in LOCALHOST_IPS:
                continue
            if conn.raddr.port not in MCP_PORT_RANGE:
                continue
            if conn.pid is None:
                continue

            key = ("port", conn.pid, conn.raddr.port)
            current_keys.add(key)
            if key in self._seen_connections:
                continue

            await self._log_mcp_connection(
                db, conn.pid, endpoint=f"localhost:{conn.raddr.port}"
            )

        # 2. Processes with "mcp" in their command line (stdio transport,
        #    or servers not yet in an ESTABLISHED connection state)
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                cmdline = " ".join(proc.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if not _is_mcp_process(cmdline, proc.info["name"] or ""):
                continue

            key = ("proc", proc.info["pid"])
            current_keys.add(key)
            if key in self._seen_connections:
                continue

            await self._log_mcp_connection(
                db, proc.info["pid"], endpoint=f"stdio:{proc.info['name']}"
            )

        self._seen_connections = current_keys
        await db.commit()

    async def _log_mcp_connection(self, db, pid: int, endpoint: str) -> None:
        agent_name = self.attributor.get_agent_for_pid(pid)
        if agent_name is None:
            return  # not under a known agent — not our concern

        agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
        session_id = await self.attributor.sessions.touch(agent_id)
        is_approved = await self._is_approved_mcp_server(db, endpoint)
        severity = "low" if is_approved else "high"

        cur = await db.execute(
            """
            INSERT INTO events
                (agent_id, session_id, event_type, path, detail, severity)
            VALUES (?, ?, 'mcp_connect', ?, ?, ?)
            """,
            (
                agent_id,
                session_id,
                endpoint,
                json.dumps({"pid": pid, "approved": is_approved}),
                severity,
            ),
        )
        event_id = cur.lastrowid

        if not is_approved:
            await self._fire_unapproved_mcp_alert(db, agent_id, endpoint, event_id)

    async def _is_approved_mcp_server(self, db, endpoint: str) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'approved_mcp_servers'"
        )
        row = await cur.fetchone()
        if row is None:
            return False
        approved = json.loads(row["policy_value"])
        return endpoint in approved

    async def _fire_unapproved_mcp_alert(self, db, agent_id: int, endpoint: str, event_id: int) -> None:
        await self.alerter.fire_alert(
            agent_id,
            "high",
            title=f"Unapproved MCP server connection: {endpoint}",
            description=f"Agent connected to MCP server '{endpoint}', which is not in the approved_mcp_servers policy list.",
            reason="unapproved_mcp",
            event_id=event_id,
            extra_detail={"endpoint": endpoint},
        )
