from fastapi import APIRouter, HTTPException

from db.database import get_db

router = APIRouter()


@router.get("/agents")
async def get_agents():
    db = await get_db()
    cur = await db.execute("SELECT * FROM agents ORDER BY last_seen DESC")
    rows = await cur.fetchall()
    return {"agents": [dict(r) for r in rows]}


@router.get("/agents/{agent_id}/sessions")
async def get_agent_sessions(agent_id: int):
    db = await get_db()

    cur = await db.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if await cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="agent not found")

    cur = await db.execute(
        "SELECT * FROM sessions WHERE agent_id = ? ORDER BY started_at DESC",
        (agent_id,),
    )
    rows = await cur.fetchall()
    return {"sessions": [dict(r) for r in rows]}
