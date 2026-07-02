import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from config.policy import POLICY_FILE
from db.database import get_db

router = APIRouter()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _get_policy_list(db, key: str) -> list[str]:
    cur = await db.execute("SELECT policy_value FROM policy WHERE policy_key = ?", (key,))
    row = await cur.fetchone()
    return json.loads(row["policy_value"]) if row else []


async def _set_policy_list(db, key: str, values: list[str]) -> None:
    """Update the policy_key in the DB (read by attributor at runtime —
    this is the live reload, there's no separate process to restart) and
    mirror the change into the on-disk policy file so it survives restarts."""
    await db.execute(
        """
        INSERT INTO policy (policy_key, policy_value)
        VALUES (?, ?)
        ON CONFLICT(policy_key) DO UPDATE SET
            policy_value = excluded.policy_value,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, json.dumps(values)),
    )
    _write_policy_file(key, values)


def _write_policy_file(key: str, values: list[str]) -> None:
    if not POLICY_FILE.exists():
        return
    policy = json.loads(POLICY_FILE.read_text())
    policy[key] = values
    POLICY_FILE.write_text(json.dumps(policy, indent=2))


async def _add_to_policy_list(db, key: str, name: str) -> None:
    values = await _get_policy_list(db, key)
    if name not in values:
        values.append(name)
        await _set_policy_list(db, key, values)


async def _remove_from_policy_list(db, key: str, name: str) -> None:
    values = await _get_policy_list(db, key)
    if name in values:
        values.remove(name)
        await _set_policy_list(db, key, values)


def _current_status(last_seen: str | None) -> str:
    if not last_seen:
        return "inactive"
    seen = datetime.fromisoformat(last_seen.replace(" ", "T")).replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - seen).total_seconds()
    if age < 30:
        return "active"
    if age < 300:
        return "idle"
    return "inactive"


@router.get("/agents")
async def get_agents():
    db = await get_db()
    cur = await db.execute("SELECT * FROM agents ORDER BY last_seen DESC")
    rows = await cur.fetchall()
    agents = []
    for r in rows:
        agent = dict(r)
        agent["current_status"] = _current_status(agent.get("last_seen"))
        agents.append(agent)
    return {"agents": agents}


@router.post("/agents/{agent_id}/approve")
async def approve_agent(agent_id: int):
    db = await get_db()

    cur = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    agent = await cur.fetchone()
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")

    await db.execute("UPDATE agents SET approved = 1 WHERE id = ?", (agent_id,))

    await db.execute(
        """
        UPDATE alerts SET status = 'exception_approved', resolved_by = 'admin',
            resolved_at = CURRENT_TIMESTAMP, resolution_note = 'agent approved from UI'
        WHERE agent_id = ? AND severity = 'critical' AND status = 'open'
        """,
        (agent_id,),
    )

    await _add_to_policy_list(db, "approved_agents", agent["name"])
    await _remove_from_policy_list(db, "blocked_agents", agent["name"])

    await db.execute(
        """
        INSERT INTO audit_log (action, entity_type, entity_id, detail)
        VALUES ('agent_approved', 'agent', ?, ?)
        """,
        (
            agent_id,
            json.dumps({"agent_name": agent["name"], "approved_at": _now_iso()}),
        ),
    )
    await db.commit()

    cur = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    updated = await cur.fetchone()
    return dict(updated)


@router.post("/agents/{agent_id}/block")
async def block_agent(agent_id: int):
    db = await get_db()

    cur = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    agent = await cur.fetchone()
    if agent is None:
        raise HTTPException(status_code=404, detail="agent not found")

    await db.execute("UPDATE agents SET approved = 2 WHERE id = ?", (agent_id,))

    await db.execute(
        """
        UPDATE alerts SET status = 'dismissed', resolved_by = 'admin',
            resolved_at = CURRENT_TIMESTAMP, resolution_note = 'agent blocked from UI'
        WHERE agent_id = ? AND severity = 'critical' AND status = 'open'
        """,
        (agent_id,),
    )

    await _remove_from_policy_list(db, "approved_agents", agent["name"])
    await _add_to_policy_list(db, "blocked_agents", agent["name"])

    await db.execute(
        """
        INSERT INTO audit_log (action, entity_type, entity_id, detail)
        VALUES ('agent_blocked', 'agent', ?, ?)
        """,
        (
            agent_id,
            json.dumps({"agent_name": agent["name"], "blocked_at": _now_iso()}),
        ),
    )
    await db.commit()

    cur = await db.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
    updated = await cur.fetchone()
    return dict(updated)


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
