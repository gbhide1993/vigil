"""Detects MCP server connections. MCP servers typically listen on
localhost ports 8000-9000 or communicate over stdio, so detection is
best-effort: localhost connections in that port range, plus processes
whose command line mentions "mcp"."""

import asyncio
import concurrent.futures
import csv
import io
import json
import logging
import subprocess
import time

from core.alerter import Alerter
from core.attributor import Attributor
from core.red_lines import RedLines
from db.database import get_db

logger = logging.getLogger("vlaw")

POLL_INTERVAL_SECONDS = 5

MCP_PORT_RANGE = range(8000, 9001)
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost"}

# Bound on the two per-poll asyncio.to_thread(get_agent_for_pid) dispatches
# in _log_mcp_connection — that call can fall through to
# Attributor._score_behaviour's synchronous sqlite3 connection (see its
# docstring), and to_thread itself has no timeout of its own.
_AGENT_LOOKUP_TIMEOUT_SECONDS = 10


def _is_mcp_process(cmdline: str, name: str) -> bool:
    lowered = (cmdline + " " + name).lower()
    return "mcp" in lowered


def _get_connections_powershell() -> list[dict]:
    """Established-TCP-connection enumeration via Get-NetTCPConnection —
    single WMI-backed query instead of psutil.net_connections()'s
    per-connection OS lookups. Mirrors
    watchers/network_watcher.py::_get_network_connections_powershell
    (kept as its own copy here rather than a cross-module import, matching
    this codebase's existing pattern of each watcher owning its own small
    enumeration helpers).

    30s timeout covers a measured ~21s worst-case cold start. No psutil
    fallback: a fallback here would run psutil.net_connections()
    unbounded on the same thread that just waited out this timeout, which
    is exactly the "PowerShell times out, falls back to an unbounded
    psutil call" failure mode that caused this watcher to stall for 60+
    seconds. poll()'s asyncio.timeout(35) is the sole remaining safety net
    for a call that still doesn't return in time."""
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command',
             'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            logger.warning(
                "McpWatcher: Get-NetTCPConnection returned no output (returncode=%s)",
                result.returncode,
            )
            return []
        connections = []
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            try:
                connections.append({
                    'remote_addr': row.get('RemoteAddress', '').strip().strip('"'),
                    'remote_port': int(row.get('RemotePort', '0').strip().strip('"') or 0),
                    'pid': int(row.get('OwningProcess', '0').strip().strip('"') or 0),
                })
            except (ValueError, KeyError):
                continue
        return connections
    except Exception as e:
        logger.warning("McpWatcher: Get-NetTCPConnection failed: %s", e)
        return []


def _get_process_list_with_cmdline_powershell() -> list[dict]:
    """Single Get-CimInstance Win32_Process query returning {pid, name,
    cmdline} for every process — replaces psutil.process_iter() plus a
    proc.cmdline() call for every single process (the same per-process
    OpenProcess cost watchers/_process_scan_worker.py exists to isolate for
    ProcessWatcher, just needed here across every process rather than a
    narrow agent-candidate subset, since any process's command line might
    mention "mcp"). CommandLine is already a single string from WMI, unlike
    psutil's cmdline() (a list of args) — matches what _is_mcp_process
    expects directly, no join needed.

    30s timeout + no psutil fallback, same reasoning as
    _get_connections_powershell above."""
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command',
             'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | ConvertTo-Csv -NoTypeInformation'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 or not result.stdout.strip():
            logger.warning(
                "McpWatcher: Get-CimInstance Win32_Process returned no output (returncode=%s)",
                result.returncode,
            )
            return []
        procs = []
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            try:
                pid = int(row.get('ProcessId', '').strip().strip('"'))
            except (ValueError, KeyError):
                continue
            name = (row.get('Name') or '').strip().strip('"')
            cmdline = (row.get('CommandLine') or '').strip().strip('"')
            if pid:
                procs.append({'pid': pid, 'name': name, 'cmdline': cmdline})
        return procs
    except Exception as e:
        logger.warning("McpWatcher: Get-CimInstance Win32_Process failed: %s", e)
        return []


class McpWatcher:
    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self.alerter = Alerter()
        self.red_lines = RedLines()
        self._seen_connections: set[tuple] = set()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="mcp-watcher")

    def stop(self) -> None:
        self._executor.shutdown(wait=False)

    async def poll(self) -> None:
        """Both scans (_gather_port_candidates/_gather_process_candidates)
        are bounded by their own PowerShell query's
        subprocess.run(timeout=30) (_get_connections_powershell/
        _get_process_list_with_cmdline_powershell) — no psutil fallback
        (see those functions' docstrings for why). Still dispatched via
        this watcher's own dedicated thread pool executor (self._executor),
        not the loop's shared default executor, so a stuck call here can't
        starve ProcessWatcher, NetworkWatcher, or Aggregator.
        _log_mcp_connection's get_agent_for_pid lookup is separately
        bounded by asyncio.wait_for(..., timeout=_AGENT_LOOKUP_TIMEOUT_SECONDS).

        This asyncio.timeout(35) is a second, independent safety net: it
        can't stop a subprocess.run call already in flight in self._executor
        (a timed-out await doesn't kill the thread beneath it), but it does
        stop a single stuck cycle from blocking this watcher's own
        scheduling indefinitely, and bounds how long a cycle can appear
        stuck to callers like /health."""
        try:
            async with asyncio.timeout(35):
                await self._poll_body()
        except TimeoutError:
            logger.warning("McpWatcher.poll timed out after 35s -- skipping cycle")

    async def _poll_body(self) -> None:
        db = await get_db()
        current_keys: set[tuple] = set()

        loop = asyncio.get_event_loop()

        # 1. Localhost connections in the MCP port range
        port_candidates = await loop.run_in_executor(self._executor, self._gather_port_candidates)
        for pid, port in port_candidates:
            key = ("port", pid, port)
            current_keys.add(key)
            if key in self._seen_connections:
                continue

            await self._log_mcp_connection(db, pid, endpoint=f"localhost:{port}")

        # 2. Processes with "mcp" in their command line (stdio transport,
        #    or servers not yet in an ESTABLISHED connection state)
        proc_candidates = await loop.run_in_executor(self._executor, self._gather_process_candidates)
        for pid, name in proc_candidates:
            key = ("proc", pid)
            current_keys.add(key)
            if key in self._seen_connections:
                continue

            await self._log_mcp_connection(db, pid, endpoint=f"stdio:{name}")

        self._seen_connections = current_keys
        await db.commit()

    @staticmethod
    def _gather_port_candidates() -> list[tuple[int, int]]:
        """Synchronous — runs in the thread pool executor via poll(). Returns
        (pid, port) pairs for established localhost connections in the MCP
        port range. No psutil fallback — see _get_connections_powershell's
        docstring for why; an empty/failed call just means no candidates
        this cycle."""
        raw = _get_connections_powershell()
        return [
            (c["pid"], c["remote_port"])
            for c in raw
            if c["pid"] and c["remote_addr"] in LOCALHOST_IPS and c["remote_port"] in MCP_PORT_RANGE
        ]

    @staticmethod
    def _gather_process_candidates() -> list[tuple[int, str]]:
        """Synchronous — runs in the thread pool executor via poll(). Returns
        (pid, name) pairs for processes whose command line mentions "mcp".
        No psutil fallback — see _get_process_list_with_cmdline_powershell's
        docstring for why; an empty/failed call just means no candidates
        this cycle."""
        procs = _get_process_list_with_cmdline_powershell()
        return [
            (p["pid"], p["name"])
            for p in procs
            if _is_mcp_process(p["cmdline"], p["name"])
        ]

    async def _log_mcp_connection(self, db, pid: int, endpoint: str) -> None:
        # get_agent_for_pid can fall through to Attributor._score_behaviour,
        # which opens a synchronous sqlite3 connection (see its docstring).
        # asyncio.to_thread keeps that off the event loop, but has no
        # timeout of its own -- wait_for bounds how long this specific
        # lookup can hold up this method, tighter than poll()'s own outer
        # asyncio.timeout(35) safety net. A timeout here doesn't kill the
        # underlying thread (not forcibly killable), just stops awaiting
        # it, matching the same tradeoff already accepted elsewhere in this
        # codebase for the same underlying call.
        try:
            agent_name = await asyncio.wait_for(
                asyncio.to_thread(self.attributor.get_agent_for_pid, pid),
                timeout=_AGENT_LOOKUP_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.warning("McpWatcher: get_agent_for_pid timed out for pid=%d -- skipping this connection", pid)
            return
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
            await self._check_mcp_auto_approval_or_fallback(db, agent_id, agent_name, endpoint, event_id, session_id)

    async def _check_mcp_auto_approval_or_fallback(
        self, db, agent_id: int, agent_name: str, endpoint: str, event_id: int, session_id: str | None = None,
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
                session_id=session_id,
            )
            if rl8_applicable:
                return  # RL8 is the applicable rule — don't also fire the generic alert

        await self._fire_unapproved_mcp_alert(db, agent_id, endpoint, event_id, session_id)

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

    async def _fire_unapproved_mcp_alert(self, db, agent_id: int, endpoint: str, event_id: int, session_id: str | None = None) -> None:
        await self.alerter.fire_alert(
            agent_id,
            "high",
            title=f"Unapproved MCP server connection: {endpoint}",
            description=f"Agent connected to MCP server '{endpoint}', which is not in the approved_mcp_servers policy list.",
            reason="unapproved_mcp",
            event_id=event_id,
            extra_detail={"endpoint": endpoint},
            target=endpoint,
            session_id=session_id,
        )
