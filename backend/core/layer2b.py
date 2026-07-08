"""Layer 2b: rolling-window MAD (Median Absolute Deviation) anomaly
detection. Unlike Layer 2a's embedded priors (population-level, apply
from session 1) and Layer 1's baseline (this machine's full history,
14-day gate), Layer 2b compares a session against just this agent's
last few closed sessions — a robust, fast-adapting local comparison
that activates as soon as 3 historical sessions exist.

Fires independently of Layer 2a; the same session can be flagged by
both without conflict — they're different detection methods answering
different questions ("is this normal for any Claude Code session?" vs
"is this normal for how *this* agent has been behaving lately?").
"""

from datetime import datetime, timezone

from core.alerter import Alerter

MAD_THRESHOLD = 3.5

_alerter = Alerter()


def mad_score(value: float, history: list[float]) -> float:
    """Median Absolute Deviation score: how many MADs `value` sits from
    the median of `history`. Robust equivalent of a z-score, meaningful
    at N >= 3 where mean/stddev are too noisy to trust."""
    if len(history) < 3:
        return 0.0
    median = sorted(history)[len(history) // 2]
    deviations = [abs(x - median) for x in history]
    mad = sorted(deviations)[len(deviations) // 2]
    if mad < 0.001:
        return 0.0
    return abs(value - median) / mad


def _median(values: list[float]) -> float:
    return sorted(values)[len(values) // 2]


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


async def _session_metrics(session_id: str, agent_id: int, db) -> dict[str, float]:
    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND agent_id = ? AND event_type IN ('file_read', 'file_write')",
        (session_id, agent_id),
    )
    file_event_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND agent_id = ? AND event_type = 'net_connect'",
        (session_id, agent_id),
    )
    network_event_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND agent_id = ? AND event_type = 'proc_spawn'",
        (session_id, agent_id),
    )
    process_event_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT started_at, ended_at FROM sessions WHERE id = ?",
        (session_id,),
    )
    row = await cur.fetchone()
    duration_seconds = 0.0
    if row is not None and row["started_at"] and row["ended_at"]:
        duration_seconds = (_parse_ts(row["ended_at"]) - _parse_ts(row["started_at"])).total_seconds()

    return {
        "file_event_count": file_event_count,
        "network_event_count": network_event_count,
        "process_event_count": process_event_count,
        "duration_seconds": duration_seconds,
    }


async def get_session_history(agent_id: int, exclude_session_id: str, db, limit: int = 5) -> list[dict]:
    """Last `limit` closed sessions for this agent (excluding the
    current one), each with its event counts and duration. Returns []
    if fewer than 3 exist — Layer 2b stays silent until then."""
    cur = await db.execute(
        """
        SELECT id FROM sessions
        WHERE agent_id = ? AND id != ? AND ended_at IS NOT NULL
        ORDER BY ended_at DESC LIMIT ?
        """,
        (agent_id, exclude_session_id, limit),
    )
    rows = await cur.fetchall()
    if len(rows) < 3:
        return []

    history = []
    for row in rows:
        history.append(await _session_metrics(row["id"], agent_id, db))
    return history


async def score_session_2b(session_id: str, agent_id: int, agent_name: str, db) -> list[int]:
    alert_ids: list[int] = []

    try:
        history = await get_session_history(agent_id, session_id, db)
        if len(history) < 3:
            return []

        current = await _session_metrics(session_id, agent_id, db)

        metrics = [
            ("file_event_count", "files", "processed"),
            ("network_event_count", "network connections", "made"),
            ("process_event_count", "processes", "spawned"),
            ("duration_seconds", "session duration", "ran for"),
        ]

        for metric_name, noun, verb in metrics:
            current_value = current[metric_name]
            history_values = [h[metric_name] for h in history]

            score = mad_score(current_value, history_values)
            if score <= MAD_THRESHOLD:
                continue

            median = _median(history_values)
            multiplier = round(current_value / max(median, 1), 1)

            severity = "high" if score > 6.0 else "medium"

            if metric_name == "duration_seconds":
                title = f"{agent_name} session ran {multiplier}x longer than its last {len(history)} sessions"
            else:
                title = f"{agent_name} {verb} {multiplier}x more {noun} than its last {len(history)} sessions"

            description = (
                f"MAD score: {score:.1f}. Current: {current_value}, "
                f"recent median: {median:.0f} (last {len(history)} sessions)"
            )

            alert_id = await _alerter.fire_alert(
                agent_id,
                severity,
                title=title,
                description=description,
                reason="rolling_anomaly",
                extra_detail={
                    "session_id": session_id,
                    "metric": metric_name,
                    "mad_score": round(score, 2),
                    "current_value": current_value,
                    "median": median,
                },
                rule_type="rolling_anomaly",
                target=metric_name,
            )
            alert_ids.append(alert_id)
    except Exception as e:
        print(f"Layer2b scoring failed: {e}")

    return alert_ids
