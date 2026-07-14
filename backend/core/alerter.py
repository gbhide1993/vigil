"""Central alert generation. Every alert in the system — regardless of
which watcher or layer detected it — is created through fire_alert() so
severity rules and audit logging stay consistent in one place.

Severity rules (per policy / Frank Besadesky model):
  CRITICAL: unapproved agent detected running
  HIGH:     credential path accessed (~/.ssh, *.pem, etc.)
  HIGH:     unapproved MCP server connected
  MEDIUM:   .env file accessed
  MEDIUM:   out-of-scope directory accessed
  MEDIUM:   suspicious command spawned
  LOW:      unapproved network destination
  LOW:      anomaly score > 0.7
"""

import fnmatch
import json
import os
import time

from db.database import get_db

SEVERITIES = ("low", "medium", "high", "critical")

# How long to suppress a repeat alert for the same (agent, reason, target)
# after one has already fired. Keyed by `reason` (the fine-grained string
# each call site passes, e.g. "unapproved_destination", "suspicious_command"
# "red_line_ssh_access"), not `rule_type` (which is just "policy"/"red_line").
DEDUP_WINDOWS = {
    "credential_access":         300,   # 5 min
    "out_of_scope_access":       300,   # 5 min
    "suspicious_command":        600,   # 10 min — curl/wget/ssh in loops
    "unapproved_destination":    1800,  # 30 min per unique destination
    "unapproved_mcp":            1800,  # 30 min per unique endpoint
    "unapproved_agent":          3600,  # once per session is enough
    "anomaly_score":             3600,
    "red_line_ssh_access":       300,
    "red_line_env_outside_workspace": 300,
    "red_line_claude_cache_write":    300,
    "red_line_unknown_destination":   1800,
    "red_line_dangerous_command":     600,
    "red_line_cross_project_read":    300,
    "red_line_env_redirect":     300,   # RL7, CVE-2026-21852 pattern
    "red_line_config_exec":      300,   # RL7b, CVE-2025-59536 pattern
    "volumetric_threshold":      3600,
    "time_anomaly":              3600,
    "ratio_anomaly":             3600,
    "rolling_anomaly":           3600,
    "verification_mismatch":     3600,  # once per session is enough
}
DEFAULT_DEDUP_WINDOW = 300


class Alerter:
    def __init__(self):
        # (agent_id, reason, target) -> last-fired unix timestamp
        self._last_fired: dict[tuple, float] = {}

    async def fire_alert(
        self,
        agent_id: int,
        severity: str,
        title: str,
        description: str,
        reason: str,
        event_id: int | None = None,
        extra_detail: dict | None = None,
        rule_type: str = "policy",
        target: str | None = None,
    ) -> int | None:
        """Create an alert row and its corresponding audit_log entry.
        Returns the new alert's id, or None if the alert was suppressed
        (deduped against a recent identical alert, or matched a user-defined
        noise suppression)."""
        if severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {severity}")

        db = await get_db()

        dedup_key = (agent_id, reason, target)
        window = DEDUP_WINDOWS.get(reason, DEFAULT_DEDUP_WINDOW)
        now = time.time()
        last = self._last_fired.get(dedup_key)
        if last is not None and now - last < window:
            return None
        self._last_fired[dedup_key] = now

        if await self._is_suppressed(db, agent_id, rule_type, reason, target):
            await self._increment_stat(db, "suppressed_alerts")
            return None

        cur = await db.execute(
            """
            INSERT INTO alerts (event_id, agent_id, severity, title, description, rule_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_id, agent_id, severity, title, description, rule_type),
        )
        alert_id = cur.lastrowid

        detail = {"reason": reason, "alert_id": alert_id, "rule_type": rule_type}
        if extra_detail:
            detail.update(extra_detail)

        await db.execute(
            """
            INSERT INTO audit_log (action, entity_type, entity_id, detail)
            VALUES ('alert_created', 'agent', ?, ?)
            """,
            (agent_id, json.dumps(detail)),
        )
        await db.commit()
        return alert_id

    async def _is_suppressed(self, db, agent_id: int, rule_type: str, reason: str, target: str | None) -> bool:
        cur = await db.execute("SELECT name FROM agents WHERE id = ?", (agent_id,))
        row = await cur.fetchone()
        agent_name = row["name"] if row else None

        cur = await db.execute(
            "SELECT agent_name, rule_type, target_pattern FROM noise_suppressions"
        )
        for supp in await cur.fetchall():
            if supp["agent_name"] and supp["agent_name"] != agent_name:
                continue
            if supp["rule_type"] and supp["rule_type"] not in (rule_type, reason):
                continue
            pattern = supp["target_pattern"]
            if pattern and (target is None or pattern not in target):
                continue
            return True
        return False

    async def _increment_stat(self, db, key: str) -> None:
        await db.execute(
            """
            INSERT INTO stats_kv (key, value) VALUES (?, 1)
            ON CONFLICT(key) DO UPDATE SET value = value + 1
            """,
            (key,),
        )
        await db.commit()

    # --- Policy-driven rules not owned by a specific watcher ---------

    async def check_credential_access(self, agent_id: int, path: str, event_id: int | None = None) -> None:
        """HIGH: credential path accessed. MEDIUM instead for .env
        specifically, per the severity table."""
        is_dotenv = os.path.basename(path) == ".env"
        severity = "medium" if is_dotenv else "high"
        await self.fire_alert(
            agent_id,
            severity,
            title=f"Credential path accessed: {path}",
            description=f"Agent accessed a credential-sensitive path: {path}",
            reason="credential_access",
            event_id=event_id,
            extra_detail={"path": path},
            target=path,
        )

    async def check_out_of_scope_access(self, agent_id: int, path: str, event_id: int | None = None) -> None:
        """MEDIUM: path accessed outside policy scope_directories, or
        CRITICAL if inside never_scope_directories."""
        db = await get_db()

        host_root = os.environ.get("VLAW_HOST_ROOT", "")
        never_scope = await self._get_policy_list(db, "never_scope_directories")
        scope_dirs = await self._get_policy_list(db, "scope_directories")

        expanded_never = [host_root + os.path.expanduser(p) for p in never_scope]
        if any(self._path_matches(path, p) for p in expanded_never):
            await self.fire_alert(
                agent_id,
                "critical",
                title=f"Data boundary violation: {path}",
                description=f"Agent accessed a path inside never_scope_directories: {path}",
                reason="data_boundary_violation",
                event_id=event_id,
                extra_detail={"path": path},
                target=path,
            )
            return

        expanded_scope = [host_root + os.path.expanduser(p) for p in scope_dirs]
        if scope_dirs and not any(self._path_matches(path, p) for p in expanded_scope):
            await self.fire_alert(
                agent_id,
                "medium",
                title=f"Out-of-scope directory access: {path}",
                description=f"Agent accessed {path}, which is outside the approved scope_directories.",
                reason="out_of_scope_access",
                event_id=event_id,
                extra_detail={"path": path},
                target=path,
            )

    async def check_anomaly_score(self, agent_id: int, session_id: str, anomaly_score: float) -> None:
        """LOW: anomaly score > 0.7 (only meaningful once baseline is
        active — caller is responsible for checking baseline_days_required)."""
        if anomaly_score > 0.7:
            await self.fire_alert(
                agent_id,
                "low",
                title="Session anomaly detected",
                description=f"Session {session_id} scored {anomaly_score:.2f} vs this agent's baseline.",
                reason="anomaly_score",
                extra_detail={"session_id": session_id, "anomaly_score": anomaly_score},
            )

    async def _get_policy_list(self, db, key: str) -> list[str]:
        cur = await db.execute("SELECT policy_value FROM policy WHERE policy_key = ?", (key,))
        row = await cur.fetchone()
        return json.loads(row["policy_value"]) if row else []

    def _path_matches(self, path: str, pattern: str) -> bool:
        normalized_path = path.replace("\\", "/")
        normalized_pattern = pattern.replace("\\", "/")
        if normalized_pattern.endswith("/"):
            return normalized_path.startswith(normalized_pattern) or (normalized_path + "/").startswith(normalized_pattern)
        return normalized_path.startswith(normalized_pattern) or fnmatch.fnmatch(normalized_path, normalized_pattern + "*")
