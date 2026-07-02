import json

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

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


@router.get("/alerts")
async def get_alerts(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
):
    db = await get_db()

    clauses = []
    params: list = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    cur = await db.execute(
        f"""
        SELECT al.*, a.name as agent_name
        FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        {where}
        ORDER BY al.created_at DESC
        """,
        params,
    )
    rows = await cur.fetchall()
    return {"alerts": [dict(r) for r in rows]}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, body: ResolveAlertRequest):
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400, detail=f"invalid action, must be one of {list(VALID_ACTIONS)}")

    if body.action in NOTE_REQUIRED_ACTIONS and not body.note:
        raise HTTPException(status_code=400, detail=f"resolution_note is required for action '{body.action}'")

    db = await get_db()
    cur = await db.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    if await cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="alert not found")

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

    return {"id": alert_id, "status": new_status}
