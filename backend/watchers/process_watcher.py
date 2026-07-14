"""Polls the process tree every 3 seconds looking for new processes
spawned under a known agent. Process spawns are never aggregated —
each is logged individually and immediately."""

import asyncio
import json
import re
import time

import psutil

from core.alerter import Alerter
from core.attributor import KNOWN_AGENTS, Attributor
from core.red_lines import RedLines
from db.database import get_db

POLL_INTERVAL_SECONDS = 3

# Matched against the executable's basename (argv[0]) or the "python -c"/
# "python3 -c" two-token form, never the full argv blob — a substring check
# against the whole cmdline false-positives constantly (e.g. "nc" inside
# "sync", "function", "--renderer-client-id", which every Electron
# subprocess spawn includes as flag text).
SUSPICIOUS_EXE_PATTERNS = {"curl", "wget", "ssh", "scp", "nc", "ncat"}
SUSPICIOUS_INLINE_PATTERNS = ["python -c", "python3 -c", "powershell -enc", "powershell -command"]

# Agent-config env vars checked by RL7 (core/red_lines.py::check_env_var_redirect).
# Kept here (not in red_lines.py) since this is the only place env vars are
# actually read off a live process.
RELEVANT_ENV_VARS = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "OPENAI_API_KEY",
}


def _match_known_agent_name(process_name: str) -> str | None:
    """Direct name match against core.attributor.KNOWN_AGENTS — deliberately
    does not walk the parent chain like Attributor.get_agent_for_pid does.
    RL7 needs the specific process whose own environment carries the
    redirected var, not whichever ancestor happens to be a known agent."""
    lowered = process_name.lower()
    for agent_key, process_names in KNOWN_AGENTS.items():
        if any(pn.lower() in lowered for pn in process_names):
            return agent_key
    return None


def _is_suspicious(cmdline: str, exe_basename: str) -> bool:
    exe = re.sub(r"\.(exe|bin)$", "", exe_basename.lower())
    if exe in SUSPICIOUS_EXE_PATTERNS:
        return True
    lowered = cmdline.lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_INLINE_PATTERNS)


class ProcessWatcher:
    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self.alerter = Alerter()
        self.red_lines = RedLines()
        self._known_pids: set[int] = set()

    async def poll(self) -> None:
        """Called periodically by the scheduler. Detects PIDs not seen in
        the previous poll and checks whether they were spawned under a
        known agent process tree, then independently re-scans every
        currently-running agent process for RL7 (see
        _scan_all_agent_processes_for_env_redirect) — that scan must not be
        gated behind "new PIDs this poll", since a redirect can be set on a
        process that was already running before this poll started.

        All psutil enumeration/inspection (process listing, per-process
        cmdline/exe/environ/parent lookups, and Attributor.get_agent_for_pid's
        parent-chain walk) is synchronous and OS-bound. Run directly inside
        this async def, it blocks the single asyncio event loop that also
        serves HTTP — a slow poll (many processes, slow environ() reads on
        Windows) was stalling uvicorn entirely. Every blocking gather is
        offloaded to the default thread pool executor via run_in_executor;
        only DB writes and alert firing (already async) stay on the loop."""
        loop = asyncio.get_event_loop()

        current_pids = await loop.run_in_executor(None, self._snapshot_pids)
        new_pids = current_pids - self._known_pids
        self._known_pids = current_pids

        env_redirect_hits = await loop.run_in_executor(
            None, self._scan_all_agent_processes_for_env_redirect
        )
        for hit in env_redirect_hits:
            agent_id = await self.attributor.get_or_create_agent(hit["agent_name"], hit["pid"])
            session_id = await self.attributor.sessions.touch(agent_id)
            await self.red_lines.check_env_var_redirect(
                agent_id, hit["agent_name"], session_id, hit["agent_env"], pid=hit["pid"]
            )

        if not new_pids:
            return

        spawn_infos = await loop.run_in_executor(None, self._gather_spawn_info, new_pids)

        db = await get_db()

        for info in spawn_infos:
            pid = info["pid"]
            cmdline = info["cmdline"]
            exe_name = info["exe_name"]
            exe_path = info["exe_path"]
            parent_pid = info["parent_pid"]
            agent_name = info["agent_name"]

            if agent_name is None:
                continue  # not under a known agent — not our concern

            agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
            session_id = await self.attributor.sessions.touch(agent_id)

            await self.red_lines.check_dangerous_command(agent_id, agent_name, cmdline, exe_name)

            await self._check_config_exec(agent_id, agent_name, exe_path or cmdline)

            suspicious = _is_suspicious(cmdline, exe_name)
            severity = "medium" if suspicious else "low"

            cur = await db.execute(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, severity)
                VALUES (?, ?, 'proc_spawn', ?, ?, ?)
                """,
                (
                    agent_id,
                    session_id,
                    cmdline or exe_name,
                    json.dumps({
                        "pid": pid,
                        "parent_pid": parent_pid,
                        "command": exe_name,
                        "args": info["args"],
                        "suspicious": suspicious,
                    }),
                    severity,
                ),
            )
            event_id = cur.lastrowid

            if suspicious:
                await self.alerter.fire_alert(
                    agent_id,
                    "medium",
                    title="Suspicious command spawned",
                    description=f"Agent spawned process (pid={pid}) with a suspicious command: {cmdline}",
                    reason="suspicious_command",
                    event_id=event_id,
                    extra_detail={"pid": pid, "cmdline": cmdline},
                    target=exe_path,
                )

        await db.commit()

    @staticmethod
    def _snapshot_pids() -> set[int]:
        """Synchronous — runs in the thread pool executor via poll()."""
        return set(psutil.pids())

    def _gather_spawn_info(self, pids: set[int]) -> list[dict]:
        """Synchronous — runs in the thread pool executor via poll(). Does
        every blocking psutil lookup (including Attributor.get_agent_for_pid's
        parent-chain walk) for each newly-seen PID up front, so the caller's
        async loop over the results never touches psutil directly."""
        infos = []
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                args = proc.cmdline()
                cmdline = " ".join(args)
                parent = proc.parent()
                parent_pid = parent.pid if parent else None
                exe_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            try:
                exe_path = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                exe_path = exe_name

            agent_name = self.attributor.get_agent_for_pid(pid)

            infos.append({
                "pid": pid,
                "cmdline": cmdline,
                "args": args,
                "exe_name": exe_name,
                "exe_path": exe_path,
                "parent_pid": parent_pid,
                "agent_name": agent_name,
            })
        return infos

    def _scan_all_agent_processes_for_env_redirect(self) -> list[dict]:
        """RL7: independently inspects every currently-running process whose
        name matches a known agent binary (core.attributor.KNOWN_AGENTS),
        not just PIDs newly spawned this poll and not just a single
        "first match" PID. Each matching process's own environment is
        checked on its own terms, so if 5 claude.exe processes are running
        and only one has ANTHROPIC_BASE_URL redirected, that exact PID is
        the one the alert is attributed to — see
        core.red_lines.RedLines.check_env_var_redirect's pid parameter.

        Synchronous — runs in the thread pool executor via poll(). Returns
        the matches instead of calling async DB/red_lines code directly,
        since executor threads can't await; poll() awaits on the results."""
        hits = []
        for proc in psutil.process_iter(["pid", "name"]):
            name = proc.info.get("name") or ""
            agent_name = _match_known_agent_name(name)
            if agent_name is None:
                continue

            pid = proc.info["pid"]
            try:
                full_env = proc.environ()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Best-effort: env vars are only readable while the process
                # is alive and, on Windows/macOS, only for processes owned
                # by the same user — skip this PID, never block the scan.
                continue

            agent_env = {k: v for k, v in full_env.items() if k.upper() in RELEVANT_ENV_VARS}
            if not agent_env:
                continue

            hits.append({"pid": pid, "agent_name": agent_name, "agent_env": agent_env})
        return hits

    async def _check_config_exec(self, agent_id: int, agent_name: str, spawned_path: str) -> None:
        """RL7b (CVE-2025-59536 pattern), spawn-triggered half: consumes a
        pending config write recorded by file_watcher.py (shared module-level
        state in core.red_lines) if this spawn falls within the correlation
        window. See file_watcher.py::_check_config_exec for the file-write
        half of the same rule."""
        pending = self.red_lines.pop_pending_config_write(agent_id)
        if pending is None:
            return

        db = await get_db()
        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE agent_id = ? AND ended_at IS NOT NULL",
            (agent_id,),
        )
        prior_approved_sessions = (await cur.fetchone())["c"]

        await self.red_lines.check_malicious_config_execution(
            agent_id, agent_name,
            config_path=pending["path"], config_write_ts=pending["ts"],
            triggered_event_path=spawned_path, triggered_event_ts=time.time(),
            prior_approved_sessions=prior_approved_sessions,
        )
