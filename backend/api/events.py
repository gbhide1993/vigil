from fastapi import APIRouter, Query

from core.attribution import event_attribution
from db.database import get_db

router = APIRouter()


@router.get("/events")
async def get_events(
    agent: int | None = Query(default=None),
    type: str | None = Query(default=None),
    since: str | None = Query(default=None),
    session: str | None = Query(default=None),
    limit: int = Query(default=50, le=2000),
):
    db = await get_db()

    clauses = []
    params: list = []

    if agent is not None:
        clauses.append("agent_id = ?")
        params.append(agent)
    if type is not None:
        clauses.append("event_type = ?")
        params.append(type)
    if since is not None:
        clauses.append("created_at >= ?")
        params.append(since)
    if session is not None:
        clauses.append("session_id = ?")
        params.append(session)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    cur = await db.execute(
        f"""
        SELECT e.*, a.name as agent_name
        FROM events e
        LEFT JOIN agents a ON a.id = e.agent_id
        {where}
        ORDER BY e.created_at DESC
        LIMIT ?
        """,
        params,
    )
    rows = await cur.fetchall()
    events = []
    for r in rows:
        event = dict(r)
        # File events: say how sure the agent attribution is (core/attribution.py).
        event.update(event_attribution(event))
        events.append(event)
    return {"events": events}
