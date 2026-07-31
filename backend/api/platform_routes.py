"""Root-level platform endpoints: capability negotiation and runtime
identity. Not versioned under /api — every MCP/IDE client hits these
first, before knowing anything else about this engine instance."""

import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter

from db.database import get_db

router = APIRouter(tags=["Platform"])

ENGINE_INSTANCE_ID = str(uuid.uuid4())
ENGINE_START_TIME = datetime.now(timezone.utc).isoformat()
ENGINE_START_EPOCH = time.time()

ENGINE_VERSION = "0.2.1"

CAPABILITIES = {
    "sessions": {"version": "1.0"},
    "red_lines": {"version": "1.1"},
    "timeline": {"version": "1.0"},
    "friction_findings": {"version": "1.0"},
    "mcp": {"version": "2026-07"},
    "git_hook": {"version": "1.0"},
    "evidence_export": {"version": "1.0"},
}


@router.get("/capabilities")
async def capabilities():
    return {
        "engine_version": ENGINE_VERSION,
        "api_version": "1.0",
        "capabilities": CAPABILITIES,
    }


@router.get("/engine")
async def engine():
    db = await get_db()
    try:
        cur = await db.execute("PRAGMA user_version")
        row = await cur.fetchone()
        database_schema = row[0] if row else 0
    except Exception:
        database_schema = 0

    return {
        "instance_id": ENGINE_INSTANCE_ID,
        "engine_version": ENGINE_VERSION,
        "started_at": ENGINE_START_TIME,
        "uptime_seconds": int(time.time() - ENGINE_START_EPOCH),
        "database_schema": database_schema,
        "pid": os.getpid(),
    }
