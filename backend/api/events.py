from fastapi import APIRouter, Query

from core.attribution import event_attribution
from db.database import get_db, get_read_db

router = APIRouter()


MAX_MATCHED_SESSIONS = 20
BS = chr(92)


def _like(text: str) -> str:
    """LIKE pattern for `text` with the wildcard characters escaped."""
    return text.replace(BS, BS + BS).replace("%", BS + "%").replace("_", BS + "_")


@router.get("/events")
async def get_events(
    agent: int | None = Query(default=None),
    type: str | None = Query(default=None),
    since: str | None = Query(default=None),
    session: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, le=2000),
):
    """Events, newest first. `q` is the History search box: an event matches when
    its session id starts with q (any case; the whole uuid works too) or q occurs
    in its agent name, type, path or detail. The reply then also carries `total`
    (all matches, not just this page) and `sessions` (the distinct sessions the
    matches belong to, plus any session whose id starts with q), so the page can
    show a true count and offer that session's report."""
    db = await get_read_db() if q is not None else await get_db()
    try:
        clauses = []
        params: list = []

        if agent is not None:
            clauses.append("e.agent_id = ?")
            params.append(agent)
        if type is not None:
            clauses.append("e.event_type = ?")
            params.append(type)
        if since is not None:
            clauses.append("e.created_at >= ?")
            params.append(since)
        if session is not None:
            clauses.append("e.session_id = ?")
            params.append(session)
        needle = (q or "").strip()
        if needle:
            pattern = _like(needle)
            clauses.append(
                "(e.session_id LIKE ? ESCAPE '\\' OR a.name LIKE ? ESCAPE '\\' OR e.event_type LIKE ? ESCAPE '\\'"
                " OR e.path LIKE ? ESCAPE '\\' OR e.detail LIKE ? ESCAPE '\\')"
            )
            params += [pattern + "%", f"%{pattern}%", f"%{pattern}%", f"%{pattern}%", f"%{pattern}%"]

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        source = "FROM events e LEFT JOIN agents a ON a.id = e.agent_id"

        cur = await db.execute(
            f"SELECT e.*, a.name as agent_name {source} {where} ORDER BY e.created_at DESC, e.id DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        rows = await cur.fetchall()
        events = []
        for r in rows:
            event = dict(r)
            # File events: say how sure the agent attribution is (core/attribution.py).
            event.update(event_attribution(event))
            events.append(event)
        if q is None:
            return {"events": events}

        cur = await db.execute(f"SELECT COUNT(*) c {source} {where}", params)
        total = (await cur.fetchone())["c"]
        sessions = await _matched_sessions(db, source, where, params, needle)
        return {"events": events, "total": total, "offset": offset, "sessions": sessions[:MAX_MATCHED_SESSIONS],
                "session_count": len(sessions)}
    finally:
        if q is not None:
            await db.close()


async def _matched_sessions(db, source: str, where: str, params: list, needle: str) -> list[dict]:
    """Distinct sessions behind the matched events, plus sessions whose id
    starts with the search text even if they have no event rows."""
    found: dict[str, dict] = {}
    cur = await db.execute(
        f"SELECT e.session_id sid, COUNT(*) n, MAX(e.created_at) last {source} {where} "
        "GROUP BY e.session_id ORDER BY last DESC LIMIT 200",
        params,
    )
    for row in await cur.fetchall():
        if row["sid"]:
            found[row["sid"]] = {"session_id": row["sid"], "matching_events": row["n"]}
    if needle:
        cur = await db.execute(
            "SELECT id FROM sessions WHERE id LIKE ? ESCAPE '\\' LIMIT 200", (_like(needle) + "%",),
        )
        for row in await cur.fetchall():
            found.setdefault(row["id"], {"session_id": row["id"], "matching_events": 0})
    ids = list(found)
    for start in range(0, len(ids), 50):
        chunk = ids[start:start + 50]
        cur = await db.execute(
            "SELECT s.id, s.started_at, s.ended_at, a.name agent_name FROM sessions s "
            f"LEFT JOIN agents a ON a.id = s.agent_id WHERE s.id IN ({','.join('?' * len(chunk))})",
            chunk,
        )
        for row in await cur.fetchall():
            found[row["id"]].update(started_at=row["started_at"], ended_at=row["ended_at"], agent_name=row["agent_name"])
    return sorted(found.values(), key=lambda s: s.get("started_at") or "", reverse=True)
