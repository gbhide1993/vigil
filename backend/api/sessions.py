from fastapi import APIRouter, Query

from db.database import get_db

router = APIRouter()

ANOMALY_RULE_TYPES = ("volumetric_threshold", "time_anomaly", "ratio_anomaly", "unknown_destination", "rolling_anomaly")


@router.get("/sessions")
async def get_sessions(status: str | None = Query(default=None)):
    """Global session listing across all agents. status=open restricts to
    sessions that haven't closed yet (ended_at IS NULL) — used by the tray
    for an active-agent count."""
    db = await get_db()

    where = "WHERE s.ended_at IS NULL" if status == "open" else ""
    cur = await db.execute(
        f"""
        SELECT s.*, a.name as agent_name,
            (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id AND e.event_type = 'net_connect') as net_connect_count
        FROM sessions s
        LEFT JOIN agents a ON a.id = s.agent_id
        {where}
        ORDER BY s.started_at DESC
        """
    )
    rows = await cur.fetchall()
    return {"sessions": [dict(r) for r in rows]}


@router.get("/sessions/{session_id}/top-finding")
async def get_session_top_finding(session_id: str):
    """The single most interesting alert for a closed session, in priority
    order: Red Line alert, then Layer 2a/2b anomaly, then None (caller
    falls back to a plain event-count summary). Alerts aren't linked to a
    session directly — event-driven alerts carry it via events.session_id,
    session-close alerts (Layer 2a/2b) carry it in audit_log.detail — so
    both sources are checked."""
    db = await get_db()

    async def _find(rule_type_clause: str, params: tuple) -> dict | None:
        cur = await db.execute(
            f"""
            SELECT al.* FROM alerts al
            WHERE {rule_type_clause}
              AND (
                al.event_id IN (SELECT id FROM events WHERE session_id = ?)
                OR al.id IN (
                    SELECT CAST(json_extract(detail, '$.alert_id') AS INTEGER)
                    FROM audit_log
                    WHERE action = 'alert_created' AND json_extract(detail, '$.session_id') = ?
                )
              )
            ORDER BY al.created_at ASC
            LIMIT 1
            """,
            (*params, session_id, session_id),
        )
        row = await cur.fetchone()
        return dict(row) if row else None

    red_line = await _find("al.rule_type = ?", ("red_line",))
    if red_line:
        return {"kind": "red_line", "alert": red_line}

    placeholders = ", ".join("?" for _ in ANOMALY_RULE_TYPES)
    anomaly = await _find(f"al.rule_type IN ({placeholders})", ANOMALY_RULE_TYPES)
    if anomaly:
        return {"kind": "anomaly", "alert": anomaly}

    return {"kind": None, "alert": None}
