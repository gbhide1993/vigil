"""Polls the process tree every 3 seconds looking for new processes
spawned under a known agent. Process spawns are never aggregated —
each is logged individually and immediately."""

import json
import re

import psutil

from core.alerter import Alerter
from core.attributor import Attributor
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
        known agent process tree."""
        current_pids = set(psutil.pids())
        new_pids = current_pids - self._known_pids
        self._known_pids = current_pids

        if not new_pids:
            return

        db = await get_db()

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                cmdline = " ".join(proc.cmdline())
                parent = proc.parent()
                parent_pid = parent.pid if parent else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            try:
                exe_path = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                exe_path = proc.name()

            agent_name = self.attributor.get_agent_for_pid(pid)
            if agent_name is None:
                continue  # not under a known agent — not our concern

            agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
            session_id = await self.attributor.sessions.touch(agent_id)

            exe_name = proc.name()
            await self.red_lines.check_dangerous_command(agent_id, agent_name, cmdline, exe_name)

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
                    cmdline or proc.name(),
                    json.dumps({
                        "pid": pid,
                        "parent_pid": parent_pid,
                        "command": proc.name(),
                        "args": proc.cmdline(),
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
