"""File changes of a session, in the shape the reports show.

Events are stored two ways: the real-time tiers (native observer, ETW) store
one row per change with the file's full path and, since the change type was
added, `detail.change` (create / write / move / delete); the polling tier
stores aggregated rows whose `path` is the containing directory and whose
`detail.paths` lists up to 50 files. Older rows have no `detail.change`; for
those the type falls back to what the event type says (file_write -> write,
file_delete -> delete), which cannot tell a create or move from a write.

Nothing here reads file contents; it only reshapes recorded rows.
"""

import os
from collections import Counter
from datetime import datetime, timezone

from core.attribution import attribution_for, parse_detail
from core.scope_store import _is_within, _key

FILE_CHANGE_EVENT_TYPES = ("file_write", "file_delete", "file_create", "cred_access")

# Most rows read for one session's summary; the exact total always comes from a COUNT.
MAX_ROWS_READ = 5000


def utc_iso(created_at: str | None) -> str | None:
    """A stored naive UTC timestamp as ISO 8601 with an explicit offset."""
    if not created_at:
        return created_at
    try:
        dt = datetime.fromisoformat(created_at.replace(" ", "T"))
    except ValueError:
        return created_at
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def change_type(event_type: str, detail: dict) -> str:
    recorded = detail.get("change")
    if recorded in ("create", "write", "move", "delete"):
        return recorded
    if event_type == "file_delete" or detail.get("event_type") == "file_delete":
        return "delete"
    if event_type == "file_create":
        return "create"
    return "write"


def scope_label(path: str, scope_dirs: list[str]) -> str | None:
    """"in_scope" / "outside_scope", or None when no folder is watched (then no
    label is shown: there is nothing to be outside of)."""
    if not scope_dirs:
        return None
    key = _key(path)
    return "in_scope" if any(_is_within(key, _key(d)) for d in scope_dirs) else "outside_scope"


def rows_to_changes(rows, agent_name: str | None) -> list[dict]:
    """rows: events rows (path, detail, event_type, event_source, created_at)."""
    changes: list[dict] = []
    for row in rows:
        detail = parse_detail(row["detail"])
        event_type = row["event_type"]
        confidence = detail.get("attribution_confidence")
        change = change_type(event_type, detail)
        attribution = attribution_for(agent_name, row["event_source"], confidence)
        paths = detail.get("paths")
        targets = paths if paths else ([row["path"]] if row["path"] else [])
        for path in targets:
            changes.append({
                "path": path,
                "time": utc_iso(row["created_at"]),
                "change": change,
                "attribution": attribution["attribution"],
                "attribution_label": attribution["attribution_label"],
                "attribution_confidence": confidence,
            })
    return changes


async def session_changes(db, session_id: str, agent_name: str | None, *, since: str | None = None,
                          until: str | None = None, limit: int = MAX_ROWS_READ) -> tuple[list[dict], int]:
    """(changes, total_rows): changes expanded from at most `limit` rows in
    time order; total_rows is the exact number of matching event rows."""
    marks = ",".join("?" * len(FILE_CHANGE_EVENT_TYPES))
    where = f"session_id = ? AND event_type IN ({marks})"
    args: list = [session_id, *FILE_CHANGE_EVENT_TYPES]
    if since is not None:
        where += " AND created_at >= ?"
        args.append(since)
    if until is not None:
        where += " AND created_at < ?"
        args.append(until)
    cur = await db.execute(f"SELECT COUNT(*) c FROM events WHERE {where}", args)
    total = (await cur.fetchone())["c"]
    cur = await db.execute(
        f"SELECT path, detail, event_type, event_source, created_at FROM events WHERE {where} ORDER BY id LIMIT ?",
        [*args, limit],
    )
    return rows_to_changes(await cur.fetchall(), agent_name), total


def summarise(changes: list[dict], *, max_directories: int = 10, max_paths: int = 50) -> dict:
    """Bounded summary for the daily exports."""
    by_change = Counter(c["change"] for c in changes)
    directories = Counter(os.path.dirname(c["path"].replace("\\", "/")) or "." for c in changes)
    seen: set[str] = set()
    first_paths: list[str] = []
    for c in changes:
        if c["path"] not in seen:
            seen.add(c["path"])
            first_paths.append(c["path"])
            if len(first_paths) >= max_paths:
                break
    return {
        "total": len(changes),
        "by_change": dict(by_change),
        "top_directories": [{"directory": d, "count": n} for d, n in directories.most_common(max_directories)],
        "first_paths": first_paths,
        "note": "full list in the session report",
    }
