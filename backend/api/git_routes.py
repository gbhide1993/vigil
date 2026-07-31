"""Git hook evidence endpoint. Summarizes recent AI-agent activity for a
single commit, in a shape the post-commit hook (scripts/vigil-post-commit.py)
can attach to git notes. Read-only — reuses the same friction-finding logic
as the MCP server (core/mcp_service.py) rather than re-deriving it."""

import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Query

from core.mcp_service import _derive_friction_findings, _expand_file_paths
from db.database import get_db

router = APIRouter(tags=["Git"])

VIGIL_VERSION = "0.2.1-beta"


@router.get("/git/commit-summary")
async def commit_summary(lookback_minutes: int = Query(default=60, ge=1, le=1440)):
    db = await get_db()
    since_clause = f"-{lookback_minutes} minutes"

    cur = await db.execute(
        """
        SELECT s.*, a.name as agent_name
        FROM sessions s
        LEFT JOIN agents a ON a.id = s.agent_id
        WHERE s.started_at > datetime('now', ?)
        ORDER BY s.started_at DESC
        """,
        (since_clause,),
    )
    session_rows = await cur.fetchall()
    session_ids = [row["id"] for row in session_rows]

    files_by_session: dict[str, set[str]] = {sid: set() for sid in session_ids}
    if session_ids:
        placeholders = ", ".join("?" for _ in session_ids)
        cur = await db.execute(
            f"""
            SELECT session_id, event_type, path, detail FROM events
            WHERE session_id IN ({placeholders})
              AND event_type IN ('file_write', 'file_read', 'cred_access')
            """,
            session_ids,
        )
        for row in await cur.fetchall():
            files_by_session[row["session_id"]].update(_expand_file_paths(row))

    sessions = []
    for row in session_rows:
        sid = row["id"]
        if row["ended_at"]:
            cur = await db.execute(
                "SELECT (julianday(?) - julianday(?)) * 24 * 60 as m",
                (row["ended_at"], row["started_at"]),
            )
        else:
            cur = await db.execute(
                "SELECT (julianday('now') - julianday(?)) * 24 * 60 as m",
                (row["started_at"],),
            )
        m = (await cur.fetchone())["m"]
        duration_min = int(m) if m is not None else 0

        sessions.append({
            "session_id": sid,
            "agent": row["agent_name"] or "unknown",
            "start_time": row["started_at"],
            "duration_min": duration_min,
            "files_touched": sorted(files_by_session.get(sid, set())),
        })

    raw_findings = await _derive_friction_findings(db, session_id=None)
    # Only findings belonging to a session started within the lookback
    # window are relevant to this commit.
    friction_signals = []
    confidence_by_type = {"retry_loop": 0.82, "rapid_revert": 0.85, "session_abandoned": 0.60}
    type_map = {"retry_loop": "retry_loop", "rapid_revert": "rapid_revert", "session_abandoned": "abandonment"}
    for f in raw_findings:
        if f["session_id"] not in session_ids:
            continue
        friction_signals.append({
            "type": type_map.get(f["finding_type"], f["finding_type"]),
            "confidence": confidence_by_type.get(f["finding_type"], 0.5),
            "file": f["filepath"],
            "description": f["evidence"],
            "session_id": f["session_id"],
        })

    cur = await db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE rule_type = 'red_line' AND created_at > datetime('now', ?)",
        (since_clause,),
    )
    red_lines = (await cur.fetchone())["c"]

    response = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_minutes": lookback_minutes,
        "vigil_version": VIGIL_VERSION,
        "sessions": sessions,
        "friction_signals": friction_signals,
        "red_lines": red_lines,
    }

    evidence_hash = hashlib.sha256(json.dumps(response, sort_keys=True).encode("utf-8")).hexdigest()
    response["evidence_hash"] = evidence_hash

    return response
