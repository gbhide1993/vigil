"""Polls the process tree every 3 seconds looking for new processes
spawned under a known agent. Process spawns are never aggregated —
each is logged individually and immediately."""

import json

import psutil

from core.alerter import Alerter
from core.attributor import Attributor
from db.database import get_db

POLL_INTERVAL_SECONDS = 3

SUSPICIOUS_PATTERNS = ["curl", "wget", "ssh", "scp", "nc", "python -c"]


def _is_suspicious(cmdline: str) -> bool:
    lowered = cmdline.lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_PATTERNS)


class ProcessWatcher:
    def __init__(self, attributor: Attributor):
        self.attributor = attributor
        self.alerter = Alerter()
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

            agent_name = self.attributor.get_agent_for_pid(pid)
            if agent_name is None:
                continue  # not under a known agent — not our concern

            agent_id = await self.attributor.get_or_create_agent(agent_name, pid)
            session_id = await self.attributor.sessions.touch(agent_id)

            suspicious = _is_suspicious(cmdline)
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
                )

        await db.commit()
