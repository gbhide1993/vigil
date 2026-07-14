"""Detects MCP server connections. MCP servers typically listen on
localhost ports 8000-9000 or communicate over stdio, so detection is
best-effort: localhost connections in that port range, plus processes
whose command line mentions "mcp"."""

import json
import time

import psutil

from core.alerter import Alerter
from core.attributor import Attributor
from core.red_lines import RedLines
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
        self.red_lines = RedLines()
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
            await self._check_mcp_auto_approval_or_fallback(db, agent_id, agent_name, endpoint, event_id)

    async def _check_mcp_auto_approval_or_fallback(
        self, db, agent_id: int, agent_name: str, endpoint: str, event_id: int,
    ) -> None:
        """RL8 (CVE-2026-21852 pattern): if this unapproved MCP connection
        immediately follows a .mcp.json write in an early session for this
        project, escalate to the non-disableable Red Line alert instead of
        the generic unapproved_mcp alert — see
        core.red_lines.RedLines.check_mcp_auto_approval. Falls back to the
        existing generic alert (reason=unapproved_mcp, severity=high) in
        every other case, so RL8 is purely additive: it never suppresses
        the alert this code already fired before RL8 existed."""
        pending = self.red_lines.pop_pending_mcp_config_write(agent_id)
        if pending is not None:
            prior_sessions = await self._count_prior_sessions(db, agent_id)
            rl8_applicable = await self.red_lines.check_mcp_auto_approval(
                agent_id, agent_name,
                mcp_config_path=pending["path"], config_write_ts=pending["ts"],
                mcp_endpoint=endpoint, mcp_connect_ts=time.time(),
                is_approved_server=False, prior_sessions_for_project=prior_sessions,
            )
            if rl8_applicable:
                return  # RL8 is the applicable rule — don't also fire the generic alert

        await self._fire_unapproved_mcp_alert(db, agent_id, endpoint, event_id)

    async def _count_prior_sessions(self, db, agent_id: int) -> int:
        """Sessions for this agent, used as RL8's project-directory session
        count. V-LAW runs one backend instance per active project
        (core.red_lines.SESSION_LAUNCH_DIR is a single module-level
        constant — there is no per-session project_path column in the
        sessions table), so agent-scoped session count already is
        project-scoped in this backend's actual deployment model. Mirrors
        file_watcher.py::_count_prior_approved_sessions, but counts all
        closed sessions (not just approved ones) — RL8's session-count
        condition is about project familiarity, not approval history.

        # LIMITATION: session count is agent-scoped, not project-scoped,
        # because the current deployment model runs one backend instance
        # per project (SESSION_LAUNCH_DIR is a single constant). If
        # multi-project monitoring from one backend instance is ever added,
        # this logic must be revisited to track sessions per
        # (agent, project_path) pair, not agent alone.
        """
        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE agent_id = ? AND ended_at IS NOT NULL",
            (agent_id,),
        )
        row = await cur.fetchone()
        return row["c"] if row else 0

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
            target=endpoint,
        )
