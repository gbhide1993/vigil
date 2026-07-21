"""Layer 2a: embedded-prior anomaly detection. Unlike Layer 1's learned
baseline (14-day warmup), these checks compare a just-closed session
against AGENT_PRIORS — researched starting distributions — so they fire
useful alerts from session 1.

Four independent checks, each firing its own alert(s) via Alerter:
  1. Hard threshold breach (file/network/process volume vs typical/high/critical)
  2. Time-of-day anomaly (session outside normal_hours, escalated if the
     user has also been inactive for hours)
  3. Read/write ratio anomaly (read-heavy or write-heavy vs prior ratio)
  4. Unknown network destination (not a suffix match on known_network_destinations)

score_session_2a() runs all four with independent try/except so one
check's failure never blocks the others or the session close that
triggered scoring.
"""

from datetime import datetime, timezone

from core.alerter import Alerter
from core.priors import get_prior

_alerter = Alerter()


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


async def check_hard_thresholds(session_id: str, agent_id: int, agent_name: str, prior: dict, db) -> list[int]:
    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND event_type IN ('file_read', 'file_write')",
        (session_id,),
    )
    file_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND event_type = 'net_connect'",
        (session_id,),
    )
    net_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND event_type = 'proc_spawn'",
        (session_id,),
    )
    proc_count = (await cur.fetchone())["c"]

    metrics = [
        ("file_events_per_session", file_count, "files this session", "wrote"),
        ("network_events_per_session", net_count, "network connections this session", "made"),
        ("process_spawns_per_session", proc_count, "processes this session", "spawned"),
    ]

    alert_ids: list[int] = []
    for metric_name, value, noun, verb in metrics:
        thresholds = prior[metric_name]
        if value <= thresholds["high"]:
            continue

        multiplier = round(value / thresholds["typical"], 1) if thresholds["typical"] else 0

        if value >= thresholds["critical"]:
            severity = "critical"
            title = f"{agent_name} {verb} {value} {noun} (critical threshold: {thresholds['critical']})"
        else:
            severity = "high"
            title = f"{agent_name} {verb} {value} {noun} ({multiplier}x typical)"

        alert_id = await _alerter.fire_alert(
            agent_id,
            severity,
            title=title,
            description=title,
            reason="volumetric_threshold",
            extra_detail={"metric": metric_name, "value": value, "session_id": session_id},
            rule_type="volumetric_threshold",
            target=metric_name,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    return alert_ids


async def check_time_anomaly(session_id: str, agent_id: int, agent_name: str, session_start: str, prior: dict, db) -> list[int]:
    start_dt = _parse_ts(session_start)
    hour = start_dt.hour
    normal_start, normal_end = prior["normal_hours"]

    if normal_start <= hour <= normal_end:
        return []

    hour12 = hour % 12 or 12
    am_pm = "AM" if hour < 12 else "PM"
    time_label = f"{hour12}:{start_dt.minute:02d} {am_pm}"

    cur = await db.execute(
        """
        SELECT ended_at FROM sessions
        WHERE agent_id = ? AND id != ? AND ended_at IS NOT NULL AND ended_at < ?
        ORDER BY ended_at DESC LIMIT 1
        """,
        (agent_id, session_id, session_start),
    )
    last_row = await cur.fetchone()

    severity = "high"
    title = f"{agent_name} session started at {time_label} — outside normal hours"

    if last_row is not None:
        last_activity = _parse_ts(last_row["ended_at"])
        gap_hours = (start_dt - last_activity).total_seconds() / 3600
        if gap_hours > 4:
            severity = "critical"
            title = f"{agent_name} active at {time_label} with no user activity for {round(gap_hours)} hours"

    alert_id = await _alerter.fire_alert(
        agent_id,
        severity,
        title=title,
        description=title,
        reason="time_anomaly",
        extra_detail={"session_id": session_id, "hour": hour},
        rule_type="time_anomaly",
        target=session_id,
        session_id=session_id,
    )
    return [alert_id]


async def check_ratio_anomaly(session_id: str, agent_id: int, agent_name: str, prior: dict, db) -> list[int]:
    cur = await db.execute(
        """
        SELECT
            COALESCE(SUM(CASE WHEN event_type = 'file_read' THEN file_count ELSE 0 END), 0) as reads,
            COALESCE(SUM(CASE WHEN event_type = 'file_write' THEN file_count ELSE 0 END), 0) as writes
        FROM events WHERE session_id = ?
        """,
        (session_id,),
    )
    row = await cur.fetchone()
    reads, writes = row["reads"], row["writes"]

    if reads + writes < 10:
        return []

    critical_ratio = prior["read_write_ratio"]["critical"]
    ratio = reads / max(writes, 1)

    alert_ids: list[int] = []

    if ratio > critical_ratio:
        title = f"{agent_name} read {reads} files but wrote {writes} — unusual read-heavy pattern"
        alert_id = await _alerter.fire_alert(
            agent_id, "high",
            title=title, description=title,
            reason="ratio_anomaly",
            extra_detail={"session_id": session_id, "reads": reads, "writes": writes, "ratio": round(ratio, 2)},
            rule_type="ratio_anomaly",
            target=session_id,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    if writes > reads * 3:
        title = f"{agent_name} wrote {writes} files but read only {reads} — unusual write-heavy pattern"
        alert_id = await _alerter.fire_alert(
            agent_id, "high",
            title=title, description=title,
            reason="ratio_anomaly",
            extra_detail={"session_id": session_id, "reads": reads, "writes": writes},
            rule_type="ratio_anomaly",
            target=session_id,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    return alert_ids


async def check_network_destinations(session_id: str, agent_id: int, agent_name: str, prior: dict, db) -> list[int]:
    cur = await db.execute(
        "SELECT DISTINCT path FROM events WHERE session_id = ? AND event_type = 'net_connect' AND path IS NOT NULL",
        (session_id,),
    )
    rows = await cur.fetchall()
    known = prior["known_network_destinations"]

    alert_ids: list[int] = []
    for row in rows:
        dest = row["path"]
        if dest == "localhost" or dest.startswith("127.0.0.1"):
            continue
        if any(dest.endswith(k) for k in known):
            continue

        cur = await db.execute(
            """
            SELECT id FROM alerts
            WHERE agent_id = ? AND rule_type = 'unknown_destination'
              AND description LIKE ?
              AND created_at > datetime('now', '-24 hours')
            LIMIT 1
            """,
            (agent_id, f"%{dest}%"),
        )
        if await cur.fetchone() is not None:
            continue

        title = f"{agent_name} connected to unknown destination: {dest}"
        alert_id = await _alerter.fire_alert(
            agent_id, "medium",
            title=title, description=title,
            reason="unknown_destination",
            extra_detail={"session_id": session_id, "destination": dest},
            rule_type="unknown_destination",
            target=dest,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    return alert_ids


async def score_session_2a(session_id: str, agent_id: int, agent_name: str, session_start: str, db) -> list[int]:
    prior = get_prior(agent_name)
    results: list[int] = []

    try:
        results += await check_hard_thresholds(session_id, agent_id, agent_name, prior, db)
    except Exception as e:
        print(f"Layer2a threshold check failed: {e}")
    try:
        results += await check_time_anomaly(session_id, agent_id, agent_name, session_start, prior, db)
    except Exception as e:
        print(f"Layer2a time check failed: {e}")
    try:
        results += await check_ratio_anomaly(session_id, agent_id, agent_name, prior, db)
    except Exception as e:
        print(f"Layer2a ratio check failed: {e}")
    try:
        results += await check_network_destinations(session_id, agent_id, agent_name, prior, db)
    except Exception as e:
        print(f"Layer2a network check failed: {e}")

    return results
