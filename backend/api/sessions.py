from fastapi import APIRouter, HTTPException, Query

from core.alerter import Alerter
from core.verification import build_verification_report, touches_credential_path
from db.database import get_db

router = APIRouter()
_alerter = Alerter()

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


@router.get("/sessions/{session_id}/verify")
async def verify_session(session_id: str):
    """Compares this session's agent-self-reported file activity (Claude
    Code's own .jsonl transcript) against what V-LAW independently
    observed at the OS level. See core/verification.py for the comparison
    logic. A non-empty discrepancies list fires a verification_mismatch
    alert as a side effect — that's the significant, actionable case."""
    db = await get_db()

    cur = await db.execute("SELECT id, agent_id FROM sessions WHERE id = ?", (session_id,))
    session = await cur.fetchone()
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")

    cur = await db.execute("SELECT name FROM agents WHERE id = ?", (session["agent_id"],))
    agent = await cur.fetchone()
    agent_name = agent["name"] if agent else "unknown agent"

    report = await build_verification_report(session_id, agent_name, db)

    discrepancies = report.get("discrepancies")
    if discrepancies:
        await _fire_verification_mismatch_alert(session["agent_id"], agent_name, session_id, discrepancies)

    return report


async def _fire_verification_mismatch_alert(agent_id: int, agent_name: str, session_id: str, discrepancies: list[dict]) -> None:
    has_credential_mismatch = any(
        d["seen_by"] == "os_only" and touches_credential_path(d["path"])
        for d in discrepancies
    )
    severity = "high" if has_credential_mismatch else "medium"
    count = len(discrepancies)

    await _alerter.fire_alert(
        agent_id,
        severity,
        title=f"{agent_name}'s own session log does not match observed OS activity — {count} discrepancies found",
        description=f"Session {session_id}: {count} file path(s) differ between {agent_name}'s self-reported "
                     "session transcript and what V-LAW independently observed at the OS level.",
        reason="verification_mismatch",
        extra_detail={"session_id": session_id, "discrepancy_count": count, "discrepancies": discrepancies[:50]},
        rule_type="verification_mismatch",
        target=session_id,
        session_id=session_id,
    )


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
