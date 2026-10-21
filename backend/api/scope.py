"""Watched project folders: GET / POST / DELETE /api/scope.

The list lives in the database (core/scope_store.py). Adding or removing a
folder is applied to the running file observer immediately, with no restart,
and is written to the audit log. Every response says whether that live apply
happened (`applied_live`) and, when it did not, why (`message`), so a saved
but not yet active folder is never reported as a silent success. Requests
must come from the local machine (the app-wide middleware in main.py already
checks the Host and Origin headers; this adds a check on the connecting
address).

The running observer is reached through core/runtime_state.py, never through
`import main` (see that module for why)."""

import json
import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core import runtime_state
from core.scope_store import (
    ScopeError, find_entry, get_meta, get_scope_directories, get_scope_entries, save_scope, validate_new_folder,
)
from db.database import get_db

logger = logging.getLogger("vlaw")

router = APIRouter()

_LOOPBACK = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}

RESTART_TO_WATCH = "Saved. Restart Vigil to start watching this folder."
RESTART_TO_STOP = "Saved. Restart Vigil to stop watching this folder."


class ScopeRequest(BaseModel):
    path: str


def require_localhost(request: Request) -> None:
    client = request.client.host if request.client else None
    if client not in _LOOPBACK:
        raise HTTPException(status_code=403, detail="Watched folders can only be changed from this computer.")


def _live():
    """(observer, file_handler) of the running file watcher, or (None, None)."""
    return runtime_state.state.get("observer"), runtime_state.state.get("file_handler")


def _is_etw(observer) -> bool:
    return observer is not None and not hasattr(observer, "schedule")


async def _audit(db, action: str, path: str) -> None:
    await db.execute(
        "INSERT INTO audit_log (action, entity_type, entity_id, actor, detail) VALUES (?, 'scope', NULL, 'admin', ?)",
        (action, json.dumps({"path": path})),
    )


@router.get("/scope")
async def get_scope(request: Request):
    require_localhost(request)
    from core.monitoring_status import file_watcher_tier
    from watchers.file_watcher import watched_paths

    db = await get_db()
    observer, _handler = _live()
    return {
        "folders": await get_scope_entries(db),
        "max_folders": 20,
        "file_watcher_tier": file_watcher_tier(),
        # What the running observer is actually watching right now.
        "observed_paths": watched_paths(observer) if observer is not None else [],
    }


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
    applied_live, message = False, RESTART_TO_WATCH
    if _is_etw(observer):
        from core.scope_filter import etw_scope
        etw_scope.add_root(stored)               # the ETW tier records only what is inside the watched roots
        applied_live, message = True, None
    elif observer is not None and handler is not None:
        try:
            applied_live = bool(watch_folder(observer, handler, stored))
            message = None if applied_live else RESTART_TO_WATCH
        except Exception:
            logger.exception("scope: could not start watching %s on the running observer", stored)
            applied_live, message = False, RESTART_TO_WATCH
    return {
        "path": stored,
        "applied_live": applied_live,
        "watching": applied_live,            # kept for older clients
        "message": message,
        "note": message,
        "folders": await get_scope_entries(db),
    }


@router.delete("/scope")
async def remove_scope(body: ScopeRequest, request: Request):
    require_localhost(request)
    from watchers.file_watcher import unwatch_folder, watched_paths

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
    applied_live, message = False, RESTART_TO_STOP
    if _is_etw(observer):
        from core.scope_filter import etw_scope
        etw_scope.remove_root(stored)
        applied_live, message = True, None
    elif observer is not None:
        try:
            unwatch_folder(observer, stored)
            # Applied if the observer no longer watches it (it may never have, for example
            # if the folder was missing at startup).
            still = [p for p in watched_paths(observer) if p.replace("\\", "/").rstrip("/").lower() == stored.lower().rstrip("/")]
            applied_live = not still
            message = None if applied_live else RESTART_TO_STOP
        except Exception:
            logger.exception("scope: could not stop watching %s on the running observer", stored)
            applied_live, message = False, RESTART_TO_STOP
    return {
        "path": stored,
        "applied_live": applied_live,
        "unwatched": applied_live,           # kept for older clients
        "message": message,
        "folders": await get_scope_entries(db),
    }
