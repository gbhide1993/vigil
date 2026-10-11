"""Watched project folders: GET / POST / DELETE /api/scope.

The list lives in the database (core/scope_store.py). Adding or removing a
folder takes effect immediately on the running file observer, with no
restart, and is written to the audit log. Requests must come from the local
machine (the app-wide middleware in main.py already checks the Host and
Origin headers; this adds a check on the connecting address)."""

import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.scope_store import (
    ScopeError, find_entry, get_meta, get_scope_directories, get_scope_entries, save_scope, validate_new_folder,
)
from db.database import get_db

router = APIRouter()

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


class ScopeRequest(BaseModel):
    path: str


def require_localhost(request: Request) -> None:
    client = request.client.host if request.client else None
    if client not in _LOOPBACK:
        raise HTTPException(status_code=403, detail="Watched folders can only be changed from this computer.")


def _live():
    """(observer, file_handler) of the running file watcher, or (None, None)."""
    import main as _main

    return _main._state.get("observer"), _main._state.get("file_handler")


async def _audit(db, action: str, path: str) -> None:
    await db.execute(
        "INSERT INTO audit_log (action, entity_type, entity_id, actor, detail) VALUES (?, 'scope', NULL, 'admin', ?)",
        (action, json.dumps({"path": path})),
    )


@router.get("/scope")
async def get_scope(request: Request):
    require_localhost(request)
    db = await get_db()
    from core.monitoring_status import file_watcher_tier

    return {"folders": await get_scope_entries(db), "max_folders": 20, "file_watcher_tier": file_watcher_tier()}


@router.post("/scope")
async def add_scope(body: ScopeRequest, request: Request):
    require_localhost(request)
    from datetime import datetime, timezone

    from watchers.file_watcher import watch_folder

    db = await get_db()
    existing = await get_scope_directories(db)
    try:
        stored = validate_new_folder(body.path, existing)
    except ScopeError as e:
        raise HTTPException(status_code=e.status, detail=e.message)

    meta = await get_meta(db)
    meta[stored] = {"added_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), "source": "user"}
    await save_scope(db, existing + [stored], meta)
    await _audit(db, "scope_add", stored)
    await db.commit()

    observer, handler = _live()
    watching = bool(observer is not None and handler is not None and watch_folder(observer, handler, stored))
    return {
        "path": stored,
        "watching": watching,
        "note": None if watching else "Saved. It will be watched after Vigil restarts, or already is if kernel tracing is active.",
        "folders": await get_scope_entries(db),
    }


@router.delete("/scope")
async def remove_scope(body: ScopeRequest, request: Request):
    require_localhost(request)
    from watchers.file_watcher import unwatch_folder

    db = await get_db()
    existing = await get_scope_directories(db)
    stored = find_entry(body.path, existing)
    if stored is None:
        raise HTTPException(status_code=404, detail="That folder is not in the watched list.")

    meta = await get_meta(db)
    remaining = [p for p in existing if p != stored]
    await save_scope(db, remaining, meta)
    await _audit(db, "scope_remove", stored)
    await db.commit()

    observer, _handler = _live()
    unwatched = bool(observer is not None and unwatch_folder(observer, stored))
    return {"path": stored, "unwatched": unwatched, "folders": await get_scope_entries(db)}
