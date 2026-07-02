"""Polls psutil.net_connections() every 5 seconds, maps each connection's
PID to an agent, and flags connections to destinations that are neither
in KNOWN_DESTINATIONS nor the policy's approved list.

Destination matching is done by IP, not hostname. Per-connection reverse
DNS was tried and found unreliable (can hang well past any configured
socket timeout on some OS resolver configurations), so instead the known
hostnames are forward-resolved once at startup into an IP set."""

import json
import socket

import psutil

from core.aggregator import Aggregator
from core.alerter import Alerter
from core.attributor import KNOWN_DESTINATIONS, Attributor
from db.database import get_db

POLL_INTERVAL_SECONDS = 5


def _resolve_known_destination_ips() -> dict[str, str]:
    """Forward-resolve each known hostname to its IP(s) once at startup.
    Returns {ip: hostname}. Best-effort — a hostname that fails to
    resolve is simply skipped, not retried per-poll."""
    ip_to_host: dict[str, str] = {}
    for hostname in KNOWN_DESTINATIONS:
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
        except (socket.gaierror, OSError):
            continue
        for ip in ip_list:
            ip_to_host[ip] = hostname
    return ip_to_host


class NetworkWatcher:
    def __init__(self, attributor: Attributor, aggregator: Aggregator):
        self.attributor = attributor
        self.aggregator = aggregator
        self.alerter = Alerter()
        self._seen_connections: set[tuple] = set()
        self._known_ips = _resolve_known_destination_ips()

    async def poll(self) -> None:
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return  # requires elevated privileges on some platforms

        db = await get_db()
        current_keys: set[tuple] = set()

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED or conn.raddr is None:
                continue
            if conn.pid is None:
                continue

            ip = conn.raddr.ip
            port = conn.raddr.port
            key = (conn.pid, ip, port)
            current_keys.add(key)

            if key in self._seen_connections:
                continue  # already logged this connection

            known_hostname = self._known_ips.get(ip)

            agent_name = self.attributor.get_agent_for_pid(conn.pid)
            if agent_name is None and known_hostname is not None:
                agent_name = self.attributor.get_agent_for_destination(known_hostname)

            if agent_name is None:
                continue

            agent_id = await self.attributor.get_or_create_agent(agent_name, conn.pid)
            session_id = await self.attributor.sessions.touch(agent_id)

            dest_label = known_hostname or ip
            is_approved = await self._is_approved_destination(db, dest_label, ip)

            if known_hostname is None and not is_approved:
                await self._fire_unapproved_destination_alert(db, agent_id, dest_label, port)

            await self.aggregator.ingest_net_event({
                "agent_id": agent_id,
                "session_id": session_id,
                "host": dest_label,
                "bytes_out": 0,  # per-process byte counters aren't reliably available cross-platform
            })

        self._seen_connections = current_keys
        await db.commit()

    async def _is_approved_destination(self, db, dest_label: str, ip: str) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'approved_mcp_servers'"
        )
        row = await cur.fetchone()
        if row is None:
            return False
        approved = json.loads(row["policy_value"])
        return dest_label in approved or ip in approved

    async def _fire_unapproved_destination_alert(self, db, agent_id: int, dest_label: str, port: int) -> None:
        await self.alerter.fire_alert(
            agent_id,
            "low",
            title=f"Unapproved network destination: {dest_label}",
            description=f"Agent connected to {dest_label}:{port}, which is not a known or approved destination.",
            reason="unapproved_destination",
            extra_detail={"host": dest_label, "port": port},
        )
