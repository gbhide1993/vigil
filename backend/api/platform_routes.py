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


@router.get("/debug/runtime")
async def debug_runtime():
    import asyncio
    import threading

    # Async task count
    loop = asyncio.get_event_loop()
    pending_tasks = len(asyncio.all_tasks(loop))
    thread_count = threading.active_count()

    # Process stats via psutil
    try:
        import psutil
        proc = psutil.Process(os.getpid())
        memory_mb = round(proc.memory_info().rss / 1024 / 1024, 1)
        cpu_percent = proc.cpu_percent(interval=0.1)
        open_files = len(proc.open_files())
    except Exception:
        memory_mb = cpu_percent = open_files = -1

    # Scheduler jobs
    try:
        import main as _main
        scheduler = _main._state.get("scheduler")
        jobs = [
            {
                "id": job.id,
                "next_run": str(job.next_run_time),
                "pending": getattr(job, 'pending', False)
            }
            for job in scheduler.get_jobs()
        ] if scheduler else []
    except Exception as e:
        jobs = [{"error": str(e)}]

    # Aggregator queue depth
    try:
        import main as _main
        aggregator = _main._state.get("aggregator")
        queue_depth = aggregator._write_queue.qsize() if aggregator else -1
    except Exception:
        queue_depth = -1

    # Uptime
    try:
        uptime_seconds = int(time.time() - ENGINE_START_EPOCH)
    except Exception:
        uptime_seconds = -1

    return {
        "uptime_seconds": uptime_seconds,
        "pending_async_tasks": pending_tasks,
        "thread_count": thread_count,
        "memory_mb": memory_mb,
        "cpu_percent": cpu_percent,
        "open_files": open_files,
        "aggregator_queue_depth": queue_depth,
        "scheduler_jobs": jobs
    }
