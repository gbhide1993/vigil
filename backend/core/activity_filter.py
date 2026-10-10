"""Shared calibration rules for the session-level volume and anomaly alerts
(Layer 2a priors, Layer 2b rolling window). Kept in one module so both
layers, the merged "Unusual activity volume" alert and the offline replay
script (scripts/replay_alert_calibration.py) apply exactly the same rules.

Nothing here touches the Red Line rules in core/red_lines.py; those fire
independently and are never capped, floored or merged by this module.

Rules implemented here:
  1. Generated/dependency paths and helper processes do not count toward
     file-write or process volume.
  2. Absolute floors (FILE_WRITE_FLOOR, PROCESS_FLOOR, NETWORK_FLOOR), at
     least 3x a floored baseline, and at least MIN_HISTORY_SESSIONS
     non-resumed history sessions before any history-based alert.
  3. Severity is capped at MEDIUM unless the session is corroborated by a
     red-line, credential, network or MCP signal; CRITICAL needs a red line.
  5. Volume findings from both layers are merged into one alert per session.
"""

import json
import re
from dataclasses import dataclass

# ------------------------------------------------------------------ rule 1

# Directory names (as whole path components) whose contents are generated
# or installed rather than written by the agent as work product.
GENERATED_SEGMENTS = (
    "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".git",
    ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".next",
    ".nuxt", "site-packages", ".gradle", ".npm", "Cache", "Code Cache", "GPUCache",
)
_GENERATED_RE = re.compile(
    r"(?:^|[\\/])(?:" + "|".join(re.escape(s) for s in GENERATED_SEGMENTS) + r")(?:[\\/]|$)",
    re.IGNORECASE,
)

# Console hosts, shells and agent wrapper/self processes: every command an
# agent runs is wrapped in one or more of these, so counting them turns
# "number of commands" into "number of commands x wrapper depth".
HELPER_PROCESS_NAMES = frozenset({
    "conhost", "cmd", "bash", "sh", "powershell", "pwsh", "claude", "codex",
    "codex-windows-sandbox-service", "werfault", "wslhost",
    "vigil-backend", "vlaw-backend", "onedrive.sync.service",
})


def is_generated_path(path: str | None) -> bool:
    return bool(path) and bool(_GENERATED_RE.search(path))


def _process_stem(name: str) -> str:
    name = (name or "").strip().lower().replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"\.(exe|bin)$", "", name)


def is_helper_process(command_name: str | None) -> bool:
    return _process_stem(command_name or "") in HELPER_PROCESS_NAMES


# ------------------------------------------------------------------ rule 2

FILE_WRITE_FLOOR = 300
PROCESS_FLOOR = 150
NETWORK_FLOOR = 100          # not specified by policy; same shape as the two above
BASELINE_MULTIPLIER = 3.0
MIN_HISTORY_SESSIONS = 5
# A baseline is never treated as smaller than a third of the absolute floor,
# so "3x the floored baseline" is never below the floor itself.
BASELINE_MIN = {
    "file_writes": FILE_WRITE_FLOOR / BASELINE_MULTIPLIER,
    "processes": PROCESS_FLOOR / BASELINE_MULTIPLIER,
    "network": NETWORK_FLOOR / BASELINE_MULTIPLIER,
}
FLOORS = {"file_writes": FILE_WRITE_FLOOR, "processes": PROCESS_FLOOR, "network": NETWORK_FLOOR}
LABELS = {
    "file_writes": ("file writes", "wrote"),
    "processes": ("processes", "spawned"),
    "network": ("network connections", "made"),
}
PRIOR_KEYS = {
    "file_writes": "file_events_per_session",
    "processes": "process_spawns_per_session",
    "network": "network_events_per_session",
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Contribution:
    metric: str
    value: int
    base_severity: str
    source: str          # "prior" (Layer 2a) or "rolling" (Layer 2b)
    detail: str


def evaluate_prior_volume(metrics: dict, prior: dict) -> list[Contribution]:
    """Layer 2a: value must exceed the prior's "high" threshold AND the
    absolute floor AND 3x the floored prior "typical"."""
    out = []
    for metric, floor in FLOORS.items():
        thresholds = prior[PRIOR_KEYS[metric]]
        value = metrics.get(metric, 0)
        baseline = max(thresholds["typical"], BASELINE_MIN[metric])
        if value <= thresholds["high"] or value < floor or value < BASELINE_MULTIPLIER * baseline:
            continue
        severity = "critical" if value >= thresholds["critical"] else "high"
        noun = LABELS[metric][0]
        out.append(Contribution(
            metric, value, severity, "prior",
            f"{noun}: {value} ({round(value / baseline, 1)}x typical; floor {floor})",
        ))
    return out


def evaluate_rolling_volume(
    metrics: dict, history: list[dict], mad_score, mad_threshold: float,
) -> list[Contribution]:
    """Layer 2b: needs MIN_HISTORY_SESSIONS history sessions; value must be
    above the median, above the absolute floor, at least 3x the floored
    median, and beyond mad_threshold MADs."""
    if len(history) < MIN_HISTORY_SESSIONS:
        return []
    out = []
    for metric, floor in FLOORS.items():
        value = metrics.get(metric, 0)
        values = [h.get(metric, 0) for h in history]
        median = sorted(values)[len(values) // 2]
        baseline = max(median, BASELINE_MIN[metric])
        if value <= median or value < floor or value < BASELINE_MULTIPLIER * baseline:
            continue
        score = mad_score(value, values)
        if score <= mad_threshold:
            continue
        severity = "high" if score > 6.0 else "medium"
        noun = LABELS[metric][0]
        out.append(Contribution(
            metric, value, severity, "rolling",
            f"{noun}: {value} vs recent median {median:.0f} ({round(value / max(baseline, 1), 1)}x, "
            f"MAD score {score:.1f}, last {len(history)} sessions)",
        ))
    return out


# ------------------------------------------------------------------ rule 3

@dataclass
class Corroboration:
    red_line: bool = False
    credential: bool = False
    network: bool = False
    mcp: bool = False

    @property
    def any(self) -> bool:
        return self.red_line or self.credential or self.network or self.mcp

    def names(self) -> list[str]:
        return [n for n, v in (("red line", self.red_line), ("credential access", self.credential),
                               ("network", self.network), ("MCP", self.mcp)) if v]


def cap_severity(base: str, corroboration: Corroboration) -> str:
    """MEDIUM unless corroborated; HIGH when corroborated by anything;
    CRITICAL only when a red-line alert is part of the corroboration."""
    if corroboration.red_line:
        ceiling = "critical"
    elif corroboration.any:
        ceiling = "high"
    else:
        ceiling = "medium"
    return base if SEVERITY_ORDER[base] <= SEVERITY_ORDER[ceiling] else ceiling


async def get_corroboration(db, session_id: str, agent_id: int) -> Corroboration:
    c = Corroboration()
    # Red-line alerts at medium or above count as a red-line signal. The
    # low-severity red-line "unrecognised network destination" alert is a
    # network signal (it corroborates up to HIGH, not CRITICAL): it fires
    # for any connection to a host outside the allow-list, so on its own it
    # says little about the rest of the session.
    cur = await db.execute(
        """
        SELECT 1 FROM alerts
        WHERE agent_id = ? AND rule_type = 'red_line' AND severity != 'low'
          AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?))
        LIMIT 1
        """,
        (agent_id, session_id, session_id),
    )
    c.red_line = await cur.fetchone() is not None

    cur = await db.execute(
        "SELECT 1 FROM events WHERE session_id = ? AND agent_id = ? AND event_type = 'cred_access' LIMIT 1",
        (session_id, agent_id),
    )
    c.credential = await cur.fetchone() is not None

    cur = await db.execute(
        """
        SELECT 1 FROM alerts
        WHERE agent_id = ?
          AND (rule_type = 'unknown_destination' OR (rule_type = 'red_line' AND severity = 'low'))
          AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?))
        LIMIT 1
        """,
        (agent_id, session_id, session_id),
    )
    c.network = await cur.fetchone() is not None

    cur = await db.execute(
        """
        SELECT 1 FROM alerts
        WHERE agent_id = ? AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?))
          AND (reason LIKE '%mcp%' OR rule_type LIKE '%mcp%')
        LIMIT 1
        """,
        (agent_id, session_id, session_id),
    )
    c.mcp = await cur.fetchone() is not None
    return c


# --------------------------------------------------------------- metrics

async def session_volume_metrics(db, session_id: str, agent_id: int) -> dict:
    """Filtered volume counts for one session: file writes (generated and
    dependency paths excluded), processes (helper processes and processes
    running from generated/dependency paths excluded), network connections."""
    cur = await db.execute(
        "SELECT path, file_count, detail FROM events "
        "WHERE session_id = ? AND agent_id = ? AND event_type = 'file_write'",
        (session_id, agent_id),
    )
    file_writes = 0
    for row in await cur.fetchall():
        if is_generated_path(row["path"]):
            continue
        count = row["file_count"] if row["file_count"] is not None else 1
        # Aggregated rows carry the real per-file paths in detail.paths
        # (capped at 50). When that list covers the whole row, drop the
        # generated ones individually.
        try:
            paths = (json.loads(row["detail"]) if row["detail"] else {}).get("paths")
        except (ValueError, AttributeError):
            paths = None
        if paths and len(paths) >= count:
            count = sum(1 for p in paths if not is_generated_path(p))
        file_writes += count

    cur = await db.execute(
        "SELECT path, detail FROM events WHERE session_id = ? AND agent_id = ? AND event_type = 'proc_spawn'",
        (session_id, agent_id),
    )
    processes = 0
    for row in await cur.fetchall():
        try:
            detail = json.loads(row["detail"]) if row["detail"] else {}
        except ValueError:
            detail = {}
        command = detail.get("command") if isinstance(detail, dict) else None
        if is_helper_process(command or row["path"]):
            continue
        if is_generated_path(row["path"]):
            continue
        processes += 1

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND agent_id = ? AND event_type = 'net_connect'",
        (session_id, agent_id),
    )
    network = (await cur.fetchone())["c"]

    return {"file_writes": file_writes, "processes": processes, "network": network}


# ------------------------------------------------------------------ rule 5

VOLUME_ALERT_TITLE = "Unusual activity volume"
VOLUME_ALERT_REASON = "volume_anomaly"


def describe_contributions(agent_name: str, contributions: list[Contribution], corroboration: Corroboration) -> str:
    parts = "; ".join(c.detail for c in contributions)
    text = f"{agent_name} had unusual activity volume this session. Contributing metrics: {parts}."
    if corroboration.any:
        text += f" Corroborated by: {', '.join(corroboration.names())}."
    return text


async def fire_volume_alert(
    alerter, db, session_id: str, agent_id: int, agent_name: str, contributions: list[Contribution],
) -> int | None:
    """One "Unusual activity volume" alert per session. Layer 2a and 2b
    each call this with their own contributions; the second call folds into
    the alert the first created instead of adding another. Returns the
    alert id, or None if there was nothing to report or it was suppressed."""
    if not contributions:
        return None

    corroboration = await get_corroboration(db, session_id, agent_id)

    cur = await db.execute(
        "SELECT id, description, severity FROM alerts "
        "WHERE agent_id = ? AND session_id = ? AND reason = ? LIMIT 1",
        (agent_id, session_id, VOLUME_ALERT_REASON),
    )
    existing = await cur.fetchone()

    base = max((c.base_severity for c in contributions), key=lambda s: SEVERITY_ORDER[s])

    if existing is None:
        severity = cap_severity(base, corroboration)
        return await alerter.fire_alert(
            agent_id, severity,
            title=VOLUME_ALERT_TITLE,
            description=describe_contributions(agent_name, contributions, corroboration),
            reason=VOLUME_ALERT_REASON,
            extra_detail={
                "session_id": session_id,
                "metrics": {c.metric: c.value for c in contributions},
                "corroborated_by": corroboration.names(),
            },
            rule_type=VOLUME_ALERT_REASON,
            target=session_id,
            session_id=session_id,
        )

    # Fold into the existing alert: append the new metrics, keep the higher
    # (still capped) severity.
    merged_severity = cap_severity(
        max(base, existing["severity"], key=lambda s: SEVERITY_ORDER[s]), corroboration,
    )
    extra = "; ".join(c.detail for c in contributions)
    description = existing["description"]
    if extra not in description:
        body = description.split(" Corroborated by:", 1)[0].rstrip(".")
        description = f"{body}; {extra}."
        if corroboration.any:
            description += f" Corroborated by: {', '.join(corroboration.names())}."
    await db.execute(
        "UPDATE alerts SET description = ?, severity = ? WHERE id = ?",
        (description, merged_severity, existing["id"]),
    )
    await db.commit()
    return existing["id"]
