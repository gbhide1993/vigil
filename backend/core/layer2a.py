"""Layer 2a: embedded-prior anomaly detection. Unlike Layer 1's learned
baseline (14-day warmup), these checks compare a just-closed session
against AGENT_PRIORS — researched starting distributions — so they fire
useful alerts from session 1.

Four independent checks, each firing its own alert(s) via Alerter:
  1. Hard threshold breach (file/network/process volume vs typical/high/critical),
     calibrated by core/activity_filter.py: generated paths and helper
     processes are not counted, absolute floors apply, and all volume
     findings for a session are merged into one "Unusual activity volume"
     alert. Every severity in this module is capped at MEDIUM unless the
     session is corroborated (see activity_filter.cap_severity).
  2. Time-of-day anomaly (session outside normal_hours, escalated if the
     user has also been inactive for hours) -- an alert only when the
     session also has a corroborating signal; otherwise an info line in the
     report
  3. Read/write ratio anomaly (read-heavy or write-heavy vs prior ratio)
  4. Unknown network destination (not a suffix match on known_network_destinations),
     one alert per destination per session, none for a destination an
     earlier non-resumed session of the same agent already used in the
     last 30 days

score_session_2a() runs all four with independent try/except so one
check's failure never blocks the others or the session close that
triggered scoring.
"""

from datetime import datetime, timezone

from core.activity_filter import (
    cap_severity, evaluate_prior_volume, fire_volume_alert, get_corroboration, session_volume_metrics,
)
from core.alerter import Alerter
from core.priors import get_prior

_alerter = Alerter()

# file_read events are never produced on Windows with the current watcher
# stack: watchdog's ReadDirectoryChangesW backend only reports file
# creation/modification/move/delete, never a pure read -- confirmed against
# the live DB, 0 file_read events exist across its entire history. With
# reads structurally stuck at 0, check_ratio_anomaly's write-heavy branch
# ("wrote N files but read only 0") would fire on every qualifying session,
# always, which isn't an anomaly, it's the only possible outcome. Gated
# behind this constant instead of deleted so it can be re-enabled the
# moment a real read source exists (e.g. ETW file-read tracing, ReadFile
# auditing) without having to reconstruct the check.
FILE_READS_OBSERVABLE = False


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


def _local_tz():
    """The system's local timezone. A separate function, rather than
    inlining datetime.now().astimezone().tzinfo at the call site, so tests
    can monkeypatch it to a fixed zone and get deterministic results
    regardless of which machine or CI runner they execute on."""
    return datetime.now().astimezone().tzinfo


async def check_hard_thresholds(session_id: str, agent_id: int, agent_name: str, prior: dict, db) -> list[int]:
    metrics = await session_volume_metrics(db, session_id, agent_id)
    contributions = evaluate_prior_volume(metrics, prior)
    alert_id = await fire_volume_alert(_alerter, db, session_id, agent_id, agent_name, contributions)
    return [alert_id] if alert_id is not None else []


def unusual_hour_label(session_start: str, agent_name: str) -> str | None:
    """"23:40" (local time) if a session starting at session_start (UTC
    text) is outside the agent's normal hours, else None. Shared by the
    alert check below and the report's info line, so the two always agree
    on what counts as an unusual hour."""
    start_local = _parse_ts(session_start).astimezone(_local_tz())
    normal_start, normal_end = get_prior(agent_name)["normal_hours"]
    if normal_start <= start_local.hour < normal_end:
        return None
    return f"{start_local.hour:02d}:{start_local.minute:02d}"


async def check_time_anomaly(session_id: str, agent_id: int, agent_name: str, session_start: str, prior: dict, db) -> list[int]:
    # session_start is stored in UTC. normal_hours is a local-time policy
    # (people have working hours in their own timezone, not UTC), so the
    # hour and the printed time label must both be converted to local time
    # before comparing or displaying -- comparing a UTC hour against
    # normal_hours flagged a normal 11:04 AM local session (05:34 UTC, in
    # Pune at UTC+5:30) as outside normal hours.
    start_utc = _parse_ts(session_start)
    start_dt = start_utc.astimezone(_local_tz())
    hour = start_dt.hour
    normal_start, normal_end = prior["normal_hours"]

    if normal_start <= hour < normal_end:
        return []

    # An unusual hour on its own is not an alert: it only becomes one when
    # the same session also carries a credential, network, MCP or
    # (medium-or-higher) red-line signal. Otherwise the report shows it as
    # an info line (api/export.py, "started at an unusual hour").
    corroboration = await get_corroboration(db, session_id, agent_id)
    if not corroboration.any:
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
        gap_hours = (start_utc - last_activity).total_seconds() / 3600
        if gap_hours > 4:
            severity = "critical"
            title = f"{agent_name} active at {time_label} with no user activity for {round(gap_hours)} hours"

    severity = cap_severity(severity, corroboration)

    alert_id = await _alerter.fire_alert(
        agent_id,
        severity,
        title=title,
        description=title,
        reason="time_anomaly",
        extra_detail={"session_id": session_id, "hour": hour, "corroborated_by": corroboration.names()},
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
    ratio_severity = cap_severity("high", await get_corroboration(db, session_id, agent_id))

    if ratio > critical_ratio:
        title = f"{agent_name} read {reads} files but wrote {writes} — unusual read-heavy pattern"
        alert_id = await _alerter.fire_alert(
            agent_id, ratio_severity,
            title=title, description=title,
            reason="ratio_anomaly",
            extra_detail={"session_id": session_id, "reads": reads, "writes": writes, "ratio": round(ratio, 2)},
            rule_type="ratio_anomaly",
            target=session_id,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    if FILE_READS_OBSERVABLE and writes > reads * 3:
        title = f"{agent_name} wrote {writes} files but read only {reads} — unusual write-heavy pattern"
        alert_id = await _alerter.fire_alert(
            agent_id, ratio_severity,
            title=title, description=title,
            reason="ratio_anomaly",
            extra_detail={"session_id": session_id, "reads": reads, "writes": writes},
            rule_type="ratio_anomaly",
            target=session_id,
            session_id=session_id,
        )
        alert_ids.append(alert_id)

    return alert_ids


UNKNOWN_DESTINATION_REPEAT_DAYS = 30


async def unknown_destination_split(session_id: str, agent_id: int, prior: dict, db) -> tuple[list[str], list[str]]:
    """Distinct unrecognised destinations this session connected to, split
    into (new, repeat). A destination is a repeat if an earlier non-resumed
    session of the same agent connected to it within the previous
    UNKNOWN_DESTINATION_REPEAT_DAYS days (measured from this session's
    start). Only new ones raise an alert; repeats are an info count in the
    report. A session with no sessions row (or no start time) has no
    history to compare against, so everything in it is new."""
    cur = await db.execute(
        "SELECT DISTINCT path FROM events WHERE session_id = ? AND event_type = 'net_connect' AND path IS NOT NULL",
        (session_id,),
    )
    known = prior["known_network_destinations"]
    unknown: list[str] = []
    for row in await cur.fetchall():
        dest = row["path"]
        host = dest.rsplit(":", 1)[0] if dest.count(":") == 1 else dest
        if host == "localhost" or host == "127.0.0.1":
            continue
        if any(host == k or host.endswith("." + k) for k in known):
            continue
        unknown.append(dest)

    cur = await db.execute("SELECT started_at FROM sessions WHERE id = ?", (session_id,))
    session_row = await cur.fetchone()
    started = session_row["started_at"] if session_row else None
    if not started:
        return unknown, []

    new_dests: list[str] = []
    repeat_dests: list[str] = []
    for dest in unknown:
        cur = await db.execute(
            """
            SELECT 1 FROM events e JOIN sessions s ON s.id = e.session_id
            WHERE e.event_type = 'net_connect' AND e.path = ? AND s.agent_id = ?
              AND s.id != ? AND s.resumed = 0 AND s.started_at < ?
              AND e.created_at >= datetime(?, ?)
            LIMIT 1
            """,
            (dest, agent_id, session_id, started, started, f"-{UNKNOWN_DESTINATION_REPEAT_DAYS} days"),
        )
        (repeat_dests if await cur.fetchone() is not None else new_dests).append(dest)
    return new_dests, repeat_dests


async def check_network_destinations(session_id: str, agent_id: int, agent_name: str, prior: dict, db) -> list[int]:
    new_dests, _repeat = await unknown_destination_split(session_id, agent_id, prior, db)

    alert_ids: list[int] = []
    for dest in new_dests:
        # {dest} is the last thing in the description (nothing follows it
        # in that format string -- see the title/description built below),
        # so an exact-suffix match is the reliable delimiter here: it's
        # not just "contains dest" (a bare instr() would let a
        # 'api.example.com' alert suppress a later 'api.example.com.evil.net'
        # one, since the former is a substring/prefix of the latter's
        # description), it's "the description ends with exactly dest".
        cur = await db.execute(
            """
            SELECT id FROM alerts
            WHERE agent_id = ? AND rule_type = 'unknown_destination'
              AND substr(description, -length(?)) = ?
              AND created_at > datetime('now', '-24 hours')
            LIMIT 1
            """,
            (agent_id, dest, dest),
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

    # Network first: an unknown-destination alert is one of the signals
    # that lets the checks below keep a higher severity.
    try:
        results += await check_network_destinations(session_id, agent_id, agent_name, prior, db)
    except Exception as e:
        print(f"Layer2a network check failed: {e}")
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

    return results
