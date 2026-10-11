import json

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.analytics import track
from db.database import get_db, get_read_db

router = APIRouter()

VALID_ACTIONS = {
    "dismiss": "dismissed",
    "exception_approved": "exception_approved",
    "risk_accepted": "risk_accepted",
}
NOTE_REQUIRED_ACTIONS = {"exception_approved", "risk_accepted"}


def _invalidate_stats_cache() -> None:
    """/api/stats caches for _STATS_CACHE_TTL_SECONDS (main.py) so repeated
    3s polls don't each pay the query cost -- but that means resolving or
    dismissing an alert here would otherwise not be reflected in
    needs_review/alerts_open for up to that long. Deferred import (not at
    module load time) avoids a circular import, since main.py is what
    imports this router -- matches the existing pattern in
    api/platform_routes.py's scheduler/aggregator introspection."""
    import main as _main
    _main._stats_cache["data"] = None


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
    session_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    since_hours: float | None = Query(default=None, gt=0),
):
    db = await get_read_db()
    try:
        return await _get_alerts_data(db, status, severity, agent, session_id, limit, offset, since_hours)
    finally:
        await db.close()


async def _get_alerts_data(db, status, severity, agent, session_id, limit, offset, since_hours=None):
    clauses = []
    params: list = []
    if since_hours is not None:
        # Only alerts detected within the last N hours (the Status page's 24h view).
        clauses.append("al.created_at >= datetime('now', ?)")
        params.append(f"-{since_hours} hours")
    if status is not None:
        clauses.append("al.status = ?")
        params.append(status)
    if severity is not None:
        # Comma-separated (severity=high,critical), not a repeated query
        # param (?severity=high&severity=critical) -- the frontend's
        # api.js builds query strings via new URLSearchParams(params) over
        # a plain object, which has no clean way to emit the same key
        # twice, whereas a CSV string needs no change there at all.
        severities = [s.strip() for s in severity.split(",") if s.strip()]
        if severities:
            placeholders = ", ".join("?" * len(severities))
            clauses.append(f"al.severity IN ({placeholders})")
            params.extend(severities)
    if agent is not None:
        clauses.append("al.agent_id = ?")
        params.append(agent)
    if session_id is not None:
        clauses.append("COALESCE(al.session_id, e.session_id) = ?")
        params.append(session_id)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    # Same WHERE (and the same LEFT JOIN events e it depends on for the
    # session_id filter) as the row query below, minus agents/sessions --
    # those two joins only ever add SELECT-list columns, nothing any
    # filter clause references, so COUNT(*) doesn't need them.
    count_cur = await db.execute(
        f"""
        SELECT COUNT(*) as c
        FROM alerts al
        LEFT JOIN events e ON e.id = al.event_id
        {where}
        """,
        params,
    )
    total = (await count_cur.fetchone())["c"]

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
        LIMIT ? OFFSET ?
        """,
        params + [limit, offset],
    )
    rows = await cur.fetchall()
    return {
        "alerts": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(rows) < total,
    }


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
    _invalidate_stats_cache()
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
    _invalidate_stats_cache()
    return {"resolved": len(ids)}


@router.post("/alerts/resolve-older")
async def resolve_older_alerts(
    days: int = Query(default=7, ge=1, le=3650),
    dry_run: bool = Query(default=False),
    include_red_line: bool = Query(default=False),
    actor: str = Query(default="admin"),
):
    """Resolve open alerts older than `days` days in one action, to clear a
    backlog of old alerts off the dashboard. Only ever sets status to
    'resolved' plus a resolution note and an audit-log row per alert; nothing
    is deleted, so every alert stays available for audit and export.

    Red-line alerts are skipped unless include_red_line=true (the UI asks
    for that with a separate checkbox): they are the non-disableable safety
    floor and are never resolved by accident. dry_run=true changes nothing
    and returns the count and severity breakdown that a real run would
    resolve, plus how many red-line alerts it is leaving alone."""
    db = await get_db()
    cur = await db.execute(
        "SELECT id, severity, rule_type FROM alerts WHERE status = 'open' AND created_at <= datetime('now', ?)",
        (f"-{days} days",),
    )
    rows = [dict(r) for r in await cur.fetchall()]

    red_line_rows = [r for r in rows if r["rule_type"] == "red_line"]
    selected = rows if include_red_line else [r for r in rows if r["rule_type"] != "red_line"]

    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in selected:
        breakdown[r["severity"]] = breakdown.get(r["severity"], 0) + 1

    result = {
        "dry_run": dry_run,
        "days": days,
        "include_red_line": include_red_line,
        "count": len(selected),
        "by_severity": breakdown,
        "red_line_skipped": 0 if include_red_line else len(red_line_rows),
    }
    if dry_run or not selected:
        return result

    note = f"bulk resolved (older than {days} days)"
    ids = [r["id"] for r in selected]
    placeholders = ", ".join("?" for _ in ids)
    await db.execute(
        f"""
        UPDATE alerts
        SET status = 'resolved', resolved_by = ?, resolved_at = CURRENT_TIMESTAMP, resolution_note = ?
        WHERE id IN ({placeholders}) AND status = 'open'
        """,
        (actor, note, *ids),
    )
    for alert_id in ids:
        await db.execute(
            """
            INSERT INTO audit_log (action, entity_type, entity_id, actor, detail)
            VALUES ('bulk_resolve_older', 'alert', ?, ?, ?)
            """,
            (alert_id, actor, json.dumps({"note": note, "days": days, "include_red_line": include_red_line})),
        )
    await db.commit()
    _invalidate_stats_cache()
    return result


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
    _invalidate_stats_cache()

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
