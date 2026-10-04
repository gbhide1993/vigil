"""Polls established TCP connections via Get-NetTCPConnection, maps each
connection's PID to an agent, and flags connections to destinations that
are neither in KNOWN_DESTINATIONS nor the policy's approved list.

Destination matching is done by IP, not hostname. Per-connection reverse
DNS was tried and found unreliable (can hang well past any configured
socket timeout on some OS resolver configurations), so instead the known
hostnames are forward-resolved once at startup into an IP set."""

import asyncio
import concurrent.futures
import csv
import io
import json
import logging
import socket
import time

from core.aggregator import Aggregator
from core.alerter import Alerter
from core.attributor import KNOWN_DESTINATIONS, Attributor
from core.feature_flags import CORE_ONLY
from core.red_lines import RedLines
from db.database import get_db

logger = logging.getLogger("vlaw")

POLL_INTERVAL_SECONDS = 5
DNS_RESOLVE_TIMEOUT_SECONDS = 20


def _resolve_known_destination_ips() -> dict[str, str]:
    """Forward-resolve each known hostname to its IP(s) once at startup.
    Returns {ip: hostname}. Best-effort — a hostname that fails to
    resolve is simply skipped, not retried per-poll.

    socket.gethostbyname_ex has no per-call timeout parameter, so the
    only way to bound it is the process-wide default socket timeout —
    set here just for the duration of this resolution pass and always
    restored afterward, so it doesn't leak into unrelated socket use
    elsewhere in the process."""
    ip_to_host: dict[str, str] = {}
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_RESOLVE_TIMEOUT_SECONDS)
    try:
        for hostname in KNOWN_DESTINATIONS:
            try:
                _, _, ip_list = socket.gethostbyname_ex(hostname)
            except (socket.gaierror, OSError):
                continue
            for ip in ip_list:
                ip_to_host[ip] = hostname
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return ip_to_host


async def _get_network_connections_powershell() -> list[dict]:
    """Established-TCP-connection enumeration via Get-NetTCPConnection —
    single WMI-backed query instead of psutil.net_connections()'s
    per-connection OS lookups. -State Established already matches this
    module's own filtering (psutil.net_connections(kind="inet") includes
    UDP sockets too, but those never report status CONN_ESTABLISHED, so
    this returns the same established-TCP-only set the old psutil path's
    output was actually narrowed down to).

    Genuinely async (asyncio.create_subprocess_exec), not a sync
    subprocess.run() dispatched to a thread — the previous version tied up
    an executor-thread slot for the PowerShell call's whole duration; this
    one yields the event loop while waiting, same as
    process_watcher.py's _run_process_scan.

    asyncio.wait_for(timeout=35) is now the SOLE timeout bound for this
    call — poll() no longer wraps it in an outer asyncio.timeout. On
    timeout or cancellation, the subprocess is killed and reaped, then the
    exception is re-raised (not swallowed into an empty result): this
    surfaces a genuinely stuck PowerShell call as an APScheduler
    job-execution error for this cycle, rather than a silently-empty poll.
    Any other failure (bad output, non-zero exit) still just logs and
    returns [], same as an empty poll cycle."""
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            'powershell', '-NoProfile', '-NonInteractive', '-Command',
            'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Csv -NoTypeInformation',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=35)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        if proc is not None:
            proc.kill()
            await proc.wait()
        raise
    except Exception as e:
        logger.warning("NetworkWatcher: Get-NetTCPConnection failed: %s", e)
        return []

    stdout_text = stdout.decode('utf-8', errors='replace')
    if proc.returncode != 0 or not stdout_text.strip():
        logger.warning(
            "NetworkWatcher: Get-NetTCPConnection returned no output (returncode=%s)",
            proc.returncode,
        )
        return []
    connections = []
    reader = csv.DictReader(io.StringIO(stdout_text))
    for row in reader:
        try:
            connections.append({
                'local_addr': row.get('LocalAddress', '').strip().strip('"'),
                'local_port': int(row.get('LocalPort', '0').strip().strip('"') or 0),
                'remote_addr': row.get('RemoteAddress', '').strip().strip('"'),
                'remote_port': int(row.get('RemotePort', '0').strip().strip('"') or 0),
                'pid': int(row.get('OwningProcess', '0').strip().strip('"') or 0),
            })
        except (ValueError, KeyError):
            continue
    return connections


class NetworkWatcher:
    def __init__(self, attributor: Attributor, aggregator: Aggregator):
        self.attributor = attributor
        self.aggregator = aggregator
        self.alerter = Alerter()
        self.red_lines = RedLines()
        self._seen_connections: set[tuple] = set()
        self._known_ips = _resolve_known_destination_ips()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="network-watcher")
        # Rolling {domain, timestamp, pid} log for core.correlation_engine's
        # network-layer signal — kept far longer than any window a caller
        # is expected to request (get_recent_events), so a connection that
        # was established well before a file burst is still visible when
        # the burst's own window is checked against it.
        self._RECENT_EVENTS_MAX_AGE_SECONDS = 600
        self._recent_events: list[dict] = []

    def stop(self) -> None:
        self._executor.shutdown(wait=False)

    async def poll(self) -> None:
        """asyncio.timeout(35) wraps the entire poll body — both the
        PowerShell connection fetch and the resolution phase (per-
        connection Attributor.get_agent_for_pid work in self._executor).
        This is safe now that _get_network_connections_powershell handles
        its own cancellation: if this outer timeout fires while that call
        is awaiting proc.communicate(), the CancelledError it raises is
        caught inside that function, which kills and reaps the subprocess
        before re-raising — so cancelling at any point in this method
        cleanly terminates the subprocess and releases the event loop,
        instead of leaving an orphaned process behind."""
        try:
            async with asyncio.timeout(35):
                await self._poll_body()
        except TimeoutError:
            logger.warning("NetworkWatcher.poll timed out after 35s -- skipping cycle")

    async def _poll_body(self) -> None:
        raw = await _get_network_connections_powershell()

        loop = asyncio.get_event_loop()
        candidates = await loop.run_in_executor(self._executor, self._resolve_candidate_connections, raw)

        db = await get_db()
        current_keys: set[tuple] = set()
        now = time.time()

        for candidate in candidates:
            key = candidate["key"]
            current_keys.add(key)

            # Recorded for every currently-established connection, not just
            # newly-seen ones, so a long-lived connection to an LLM API
            # domain is still visible to CorrelationEngine when a file burst
            # happens later in that same connection's lifetime.
            conn_pid, ip, _port = key
            dest_label = candidate["known_hostname"] or ip
            self._recent_events.append({"domain": dest_label, "timestamp": now, "pid": conn_pid})

            if key in self._seen_connections:
                continue  # already logged this connection

            agent_name = candidate["agent_name"]
            if agent_name is None:
                continue

            conn_pid, ip, port = key
            known_hostname = candidate["known_hostname"]
            agent_id = await self.attributor.get_or_create_agent(agent_name, conn_pid)
            session_id = await self.attributor.sessions.touch(agent_id)

            dest_label = known_hostname or ip

            if not CORE_ONLY:
                await self.red_lines.check_unknown_destination(agent_id, agent_name, dest_label, session_id=session_id)

                is_approved = await self._is_approved_destination(db, dest_label, ip)

                if known_hostname is None and not is_approved:
                    await self._fire_unapproved_destination_alert(db, agent_id, dest_label, port, session_id)

            await self.aggregator.ingest_net_event({
                "agent_id": agent_id,
                "session_id": session_id,
                "host": dest_label,
                "bytes_out": 0,  # per-process byte counters aren't reliably available cross-platform
            })

        self._seen_connections = current_keys
        cutoff = now - self._RECENT_EVENTS_MAX_AGE_SECONDS
        self._recent_events = [e for e in self._recent_events if e["timestamp"] >= cutoff]
        await db.commit()

    def get_recent_events(self, window_secs: int = 90) -> list[dict]:
        """{domain, timestamp, pid} dicts observed within the last
        window_secs — read-only, no psutil call, for
        core.correlation_engine.CorrelationEngine."""
        cutoff = time.time() - window_secs
        return [e for e in self._recent_events if e["timestamp"] >= cutoff]

    def _resolve_candidate_connections(self, raw: list[dict]) -> list[dict]:
        """Synchronous — runs in the thread pool executor via _poll_body.
        Does Attributor.get_agent_for_pid's parent-chain walk per
        connection (still blocking/psutil-capable) up front, so the
        caller's async loop over the results never touches psutil
        directly. Includes already-seen connections too — poll() still
        needs the full current-key set to know what dropped off.

        `raw` is this cycle's connection list, already fetched by
        _get_network_connections_powershell — that call is genuinely async
        now and is awaited directly on the event loop in _poll_body, not
        here, so this method only does the remaining psutil-capable work."""
        established = [
            {"pid": c["pid"], "ip": c["remote_addr"], "port": c["remote_port"]}
            for c in raw
            if c["pid"] and c["remote_addr"]
        ]

        candidates = []
        for item in established:
            pid, ip, port = item["pid"], item["ip"], item["port"]
            key = (pid, ip, port)

            known_hostname = self._known_ips.get(ip)

            agent_name = self.attributor.get_agent_for_pid(pid)
            if agent_name is None and known_hostname is not None:
                agent_name = self.attributor.get_agent_for_destination(known_hostname)

            candidates.append({"key": key, "agent_name": agent_name, "known_hostname": known_hostname})
        return candidates

    async def _is_approved_destination(self, db, dest_label: str, ip: str) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'approved_network_destinations'"
        )
        row = await cur.fetchone()
        if row is None:
            return False
        approved = json.loads(row["policy_value"])
        if dest_label in approved or ip in approved:
            return True
        return any(dest_label.endswith(suffix) for suffix in approved)

    async def _fire_unapproved_destination_alert(self, db, agent_id: int, dest_label: str, port: int, session_id: str | None = None) -> None:
        await self.alerter.fire_alert(
            agent_id,
            "low",
            title=f"Unapproved network destination: {dest_label}",
            description=f"Agent connected to {dest_label}:{port}, which is not a known or approved destination.",
            reason="unapproved_destination",
            extra_detail={"host": dest_label, "port": port},
            target=dest_label,
            session_id=session_id,
        )
