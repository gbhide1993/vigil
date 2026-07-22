import json

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.analytics import track
from db.database import get_db

router = APIRouter()

VALID_ACTIONS = {
    "dismiss": "dismissed",
    "exception_approved": "exception_approved",
    "risk_accepted": "risk_accepted",
}
NOTE_REQUIRED_ACTIONS = {"exception_approved", "risk_accepted"}


class ResolveAlertRequest(BaseModel):
    action: str
    note: str | None = None
    actor: str = "admin"


class CreateSuppressionRequest(BaseModel):
    agent_name: str | None = None
    rule_type: str | None = None
    target_pattern: str | None = None
    reason: str | None = None


class BulkResolveRequest(BaseModel):
    session_id: str | None = None
    older_than_hours: float | None = None
    all: bool = False


@router.get("/alerts")
async def get_alerts(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    agent: int | None = Query(default=None),
):
    db = await get_db()

    clauses = []
    params: list = []
    if status is not None:
        clauses.append("al.status = ?")
        params.append(status)
    if severity is not None:
        clauses.append("al.severity = ?")
        params.append(severity)
    if agent is not None:
        clauses.append("al.agent_id = ?")
        params.append(agent)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    cur = await db.execute(
        f"""
        SELECT al.id, al.event_id, al.agent_id, al.severity, al.title, al.description,
            al.status, al.resolved_by, al.resolved_at, al.resolution_note, al.rule_type,
            al.created_at, a.name as agent_name,
            COALESCE(al.session_id, e.session_id) as session_id, e.path as event_path,
            s.summary as session_summary
        FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        LEFT JOIN events e ON e.id = al.event_id
        LEFT JOIN sessions s ON s.id = COALESCE(al.session_id, e.session_id)
        {where}
        ORDER BY al.created_at DESC
        """,
        params,
    )
    rows = await cur.fetchall()
    return {"alerts": [dict(r) for r in rows]}


@router.post("/alerts/bulk-dismiss")
async def bulk_dismiss(severity: str = Query(...), actor: str = Query(default="admin")):
    """Dismiss every open/investigating alert at the given severity in one
    action — used by the Alerts screen's 'Dismiss all LOW' button, since
    low-severity noise is the bulk of alert volume and dismissing one at a
    time doesn't scale. Red Line alerts are never included (rule_type check
    mirrors the single-alert resolve endpoint)."""
    if severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="invalid severity")

    db = await get_db()
    cur = await db.execute(
        "SELECT id FROM alerts WHERE severity = ? AND status IN ('open', 'investigating') AND rule_type != 'red_line'",
        (severity,),
    )
    ids = [r["id"] for r in await cur.fetchall()]
    if not ids:
        return {"dismissed": 0}

    placeholders = ", ".join("?" for _ in ids)
    await db.execute(
        f"""
        UPDATE alerts
        SET status = 'dismissed', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP,
            resolution_note = 'bulk dismissed from UI'
        WHERE id IN ({placeholders})
        """,
        (actor, *ids),
    )
    for alert_id in ids:
        await db.execute(
            """
            INSERT INTO audit_log (action, entity_type, entity_id, actor, detail)
            VALUES ('dismiss', 'alert', ?, ?, ?)
            """,
            (alert_id, actor, json.dumps({"note": "bulk dismissed from UI", "severity": severity})),
        )
    await db.commit()
    return {"dismissed": len(ids)}


@router.post("/alerts/bulk-resolve")
async def bulk_resolve(body: BulkResolveRequest, actor: str = Query(default="admin")):
    """Resolve many open alerts at once by filter — used operator-side to
    clear backlogs (e.g. pre-fix alerts with no session_id) without walking
    them one by one. Only ever updates status; never deletes, so resolved
    alerts stay in the DB for audit."""
    has_session_filter = "session_id" in body.model_fields_set
    if not has_session_filter and body.older_than_hours is None and not body.all:
        raise HTTPException(
            status_code=400,
            detail="must specify one of: session_id, older_than_hours, all",
        )

    db = await get_db()

    clauses = ["al.status IN ('open', 'investigating')", "al.rule_type != 'red_line'"]
    params: list = []

    if has_session_filter:
        if body.session_id is None:
            clauses.append(
                "al.id IN (SELECT al2.id FROM alerts al2 LEFT JOIN events e2 ON e2.id = al2.event_id "
                "WHERE COALESCE(al2.session_id, e2.session_id) IS NULL)"
            )
        else:
            clauses.append(
                "al.id IN (SELECT al2.id FROM alerts al2 LEFT JOIN events e2 ON e2.id = al2.event_id "
                "WHERE COALESCE(al2.session_id, e2.session_id) = ?)"
            )
            params.append(body.session_id)

    if body.older_than_hours is not None:
        clauses.append("al.created_at <= datetime('now', ?)")
        params.append(f"-{body.older_than_hours} hours")

    where = " AND ".join(clauses)

    cur = await db.execute(f"SELECT al.id FROM alerts al WHERE {where}", params)
    ids = [r["id"] for r in await cur.fetchall()]
    if not ids:
        return {"resolved": 0}

    placeholders = ", ".join("?" for _ in ids)
    await db.execute(
        f"""
        UPDATE alerts
        SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP,
            resolution_note = 'bulk resolved via /alerts/bulk-resolve'
        WHERE id IN ({placeholders})
        """,
        (actor, *ids),
    )
    for alert_id in ids:
        await db.execute(
            """
            INSERT INTO audit_log (action, entity_type, entity_id, actor, detail)
            VALUES ('bulk_resolve', 'alert', ?, ?, ?)
            """,
            (alert_id, actor, json.dumps(body.model_dump(exclude_unset=True))),
        )
    await db.commit()
    return {"resolved": len(ids)}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, body: ResolveAlertRequest):
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail=f"invalid action, must be one of {list(VALID_ACTIONS)}")

    if body.action in NOTE_REQUIRED_ACTIONS and not body.note:
        raise HTTPException(status_code=400, detail=f"resolution_note is required for action '{body.action}'")

    db = await get_db()
    cur = await db.execute("SELECT id, rule_type, severity FROM alerts WHERE id = ?", (alert_id,))
    alert = await cur.fetchone()
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")

    if alert["rule_type"] == "red_line":
        raise HTTPException(status_code=403, detail="Red Line alerts are a non-disableable safety floor and cannot be resolved from the UI")

    new_status = VALID_ACTIONS[body.action]

    await db.execute(
        """
        UPDATE alerts
        SET status = ?, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP, resolution_note = ?
        WHERE id = ?
        """,
        (new_status, body.actor, body.note, alert_id),
    )
    await db.execute(
        """
        INSERT INTO audit_log (action, entity_type, entity_id, actor, detail)
        VALUES (?, 'alert', ?, ?, ?)
        """,
        (
            body.action,
            alert_id,
            body.actor,
            json.dumps({"note": body.note}),
        ),
    )
    await db.commit()

    await track("alert_resolved", {"severity": alert["severity"], "rule_type": alert["rule_type"]})

    return {"id": alert_id, "status": new_status}


@router.get("/suppressions")
async def get_suppressions():
    db = await get_db()
    cur = await db.execute("SELECT * FROM noise_suppressions ORDER BY created_at DESC")
    rows = await cur.fetchall()
    return {"suppressions": [dict(r) for r in rows]}


@router.post("/suppressions")
async def create_suppression(body: CreateSuppressionRequest):
    db = await get_db()
    cur = await db.execute(
        """
        INSERT INTO noise_suppressions (agent_name, rule_type, target_pattern, reason)
        VALUES (?, ?, ?, ?)
        """,
        (body.agent_name, body.rule_type, body.target_pattern, body.reason),
    )
    await db.commit()
    return {"id": cur.lastrowid}


@router.delete("/suppressions/{suppression_id}")
async def delete_suppression(suppression_id: int):
    db = await get_db()
    cur = await db.execute("SELECT id FROM noise_suppressions WHERE id = ?", (suppression_id,))
    if await cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="suppression not found")

    await db.execute("DELETE FROM noise_suppressions WHERE id = ?", (suppression_id,))
    await db.commit()
    return {"id": suppression_id, "deleted": True}
