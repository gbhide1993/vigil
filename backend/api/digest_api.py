import json

from fastapi import APIRouter

from core.config_auditor import audit_all_configs
from db.database import get_db

router = APIRouter()

# calculate_days_clean walks backward from today at most this many days —
# a runaway-query guard for very old installations, per the brief. Not a
# claim that "clean" streaks longer than this are impossible, just a cap
# on how far back a single digest request will scan.
DAYS_CLEAN_MAX_LOOKBACK = 90

HIGH_CRITICAL_SEVERITIES = ("high", "critical")


async def calculate_days_clean(db) -> int:
    """Counts consecutive FULL days before today with zero HIGH or CRITICAL
    severity alerts — i.e. today itself is excluded (it isn't "complete"
    yet), and the count is the number of whole clean days since the most
    recent HIGH/CRITICAL incident. E.g. an incident 3 days ago (day -3)
    yields days_clean = 2 (day -1 and day -2 are clean; day -3 is not; day
    0/today isn't counted either way). Walks backward from yesterday in
    Python (not via one DB round-trip per day — an earlier version did
    that and measurably stalled the shared aiosqlite connection against
    the scheduler's own concurrent queries on a real, busy install); the
    streak stops the day a HIGH/CRITICAL alert is found. Capped at
    DAYS_CLEAN_MAX_LOOKBACK days so a very old installation with a
    long-ago incident doesn't force a full-history scan on every digest
    request."""
    from datetime import date, timedelta

    cur = await db.execute(
        f"""
        SELECT date(created_at) as day
        FROM alerts
        WHERE severity IN ('high', 'critical')
          AND date(created_at) > date('now', '-{DAYS_CLEAN_MAX_LOOKBACK} days')
        GROUP BY day
        """
    )
    rows = await cur.fetchall()
    bad_days = {row["day"] for row in rows}

    today = date.today()
    days_clean = 0
    for offset in range(1, DAYS_CLEAN_MAX_LOOKBACK + 1):
        day = (today - timedelta(days=offset)).isoformat()
        if day in bad_days:
            break
        days_clean += 1

    return days_clean


async def _count_files_monitored(db, since_clause: str) -> int:
    """Distinct file paths touched in the window. file_write/file_read
    events are aggregated (core/aggregator.py) — the row's own `path`
    column holds the containing directory, not the individual file; real
    per-file paths live in detail.paths (JSON array, capped at 50 per
    aggregation window). cred_access events are never aggregated and store
    the single real path directly on the row. Mirrors the same unpacking
    core/cross_agent.py's _expand_file_event_paths does, kept local here
    since digest only needs a distinct-path count, not the full per-event
    breakdown that helper returns."""
    cur = await db.execute(
        f"""
        SELECT event_type, path, detail FROM events
        WHERE event_type IN ('file_write', 'file_read', 'cred_access')
          AND created_at > datetime('now', '{since_clause}')
        """
    )
    rows = await cur.fetchall()

    distinct_paths: set[str] = set()
    for row in rows:
        if row["event_type"] == "cred_access":
            if row["path"]:
                distinct_paths.add(row["path"])
            continue
        detail = json.loads(row["detail"]) if row["detail"] else {}
        paths = detail.get("paths")
        if paths:
            distinct_paths.update(paths)
        elif row["path"]:
            distinct_paths.add(row["path"])

    return len(distinct_paths)


async def _build_proof_of_value(db) -> dict:
    """Every field here is a real query against existing tables — a
    genuine 0 (e.g. no agents active) is returned honestly, never omitted
    or substituted with a placeholder."""
    days_clean = await calculate_days_clean(db)

    cur = await db.execute(
        "SELECT COUNT(DISTINCT agent_id) c FROM sessions WHERE started_at > datetime('now', '-7 days')"
    )
    agents_watched = (await cur.fetchone())["c"]

    files_monitored_7d = await _count_files_monitored(db, "-7 days")

    cur = await db.execute(
        "SELECT COUNT(DISTINCT path) c FROM events WHERE event_type = 'net_connect' AND created_at > datetime('now', '-7 days')"
    )
    network_destinations_verified_7d = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM sessions WHERE started_at > datetime('now', '-7 days')"
    )
    sessions_covered_7d = (await cur.fetchone())["c"]

    audit = audit_all_configs()
    configured_count = len(audit["configured"])
    total_recommended = len(audit["configured"]) + len(audit["missing"])
    config_audit_summary = f"{configured_count}/{total_recommended} protections active"

    return {
        "days_clean": days_clean,
        "agents_watched": agents_watched,
        "files_monitored_7d": files_monitored_7d,
        "network_destinations_verified_7d": network_destinations_verified_7d,
        "config_audit_summary": config_audit_summary,
        "sessions_covered_7d": sessions_covered_7d,
    }


@router.get("/digest/daily")
async def get_daily_digest():
    db = await get_db()

    cur = await db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE created_at > datetime('now', '-24 hours')"
    )
    alerts_24h = (await cur.fetchone())["c"]

    # checkpoint_activity (RL3's normal-/rewind tier — see core/red_lines.py)
    # is expected, frequent, benign background noise, not a "meaningful
    # alert" — excluded here so the digest summary and "clean" flag reflect
    # what's actually worth a human's attention, not raw checkpoint volume.
    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts
        WHERE created_at > datetime('now', '-24 hours') AND rule_type != 'checkpoint_activity'
        """
    )
    meaningful_alerts_24h = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts
        WHERE created_at > datetime('now', '-24 hours') AND rule_type = 'red_line'
        """
    )
    red_line_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts
        WHERE created_at > datetime('now', '-24 hours')
          AND rule_type IN ('volumetric_threshold', 'time_anomaly', 'ratio_anomaly', 'unknown_destination', 'rolling_anomaly')
        """
    )
    anomaly_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT DISTINCT a.name FROM sessions s
        JOIN agents a ON a.id = s.agent_id
        WHERE s.started_at > datetime('now', '-24 hours')
           OR s.ended_at > datetime('now', '-24 hours')
           OR (s.ended_at IS NULL AND s.started_at IS NOT NULL)
        ORDER BY a.name
        """
    )
    agent_rows = await cur.fetchall()
    agent_names = [row["name"] for row in agent_rows]
    agents_active = len(agent_names)

    clean = meaningful_alerts_24h == 0

    if clean:
        summary = "All clear. No alerts in the last 24 hours."
    else:
        summary = f"{meaningful_alerts_24h} alert{'s' if meaningful_alerts_24h != 1 else ''} in the last 24h."
        if red_line_count:
            summary += f" {red_line_count} RED LINE."
        if agent_names:
            summary += f" {', '.join(agent_names)} active."
        if anomaly_count:
            summary += f" {anomaly_count} behavioral anomaly detected."
        summary = summary[:100]

    proof_of_value = await _build_proof_of_value(db)

    return {
        "alerts_24h": alerts_24h,
        "meaningful_alerts_24h": meaningful_alerts_24h,
        "red_line_count": red_line_count,
        "agents_active": agents_active,
        "clean": clean,
        "summary": summary,
        "proof_of_value": proof_of_value,
    }


@router.get("/digest/proof-of-value")
async def get_proof_of_value():
    """Standalone endpoint so the web UI's Live Feed can show this as a
    persistent card independent of the once-daily toast — same
    _build_proof_of_value() logic /digest/daily uses, not a duplicate."""
    db = await get_db()
    return await _build_proof_of_value(db)
