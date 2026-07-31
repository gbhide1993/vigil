"""Read-only query layer for the MCP server (api/mcp_routes.py). Every
function here only SELECTs from tables that watchers/aggregator already
populate — no new data collection, no writes, nothing that touches network.
"""

import hashlib
import json

from db.database import get_db, get_read_db

EVIDENCE_NOTE = (
    "All data independently observed at OS level by Vigil. "
    "Local only — no cloud transmission."
)


async def dispatch_tool(tool_name: str, params: dict) -> dict:
    """Routes to a tool handler by name. Never raises — callers (the MCP
    HTTP routes) always get a dict back, with 'error' set on failure."""
    handler = _HANDLERS.get(tool_name)
    if handler is None:
        return {"error": f"Unknown tool: {tool_name}", "result": None}

    try:
        result = await handler(params or {})
        return {"result": result, "error": None}
    except Exception as e:
        return {"error": str(e), "result": None}


def _expand_file_paths(row) -> list[str]:
    """file_write/file_read events are aggregated — the row's own `path`
    column holds the containing directory, real per-file paths live in
    detail.paths (JSON array). Mirrors api/export.py's _count_files_monitored
    unpacking. cred_access rows store the real path directly."""
    if row["event_type"] == "cred_access":
        return [row["path"]] if row["path"] else []
    detail = json.loads(row["detail"]) if row["detail"] else {}
    paths = detail.get("paths")
    if paths:
        return paths
    return [row["path"]] if row["path"] else []


async def _get_current_session(params: dict) -> dict:
    db = await get_db()

    cur = await db.execute(
        """
        SELECT s.*, a.name as agent_name
        FROM sessions s
        LEFT JOIN agents a ON a.id = s.agent_id
        WHERE s.ended_at IS NULL
        ORDER BY s.started_at DESC
        LIMIT 1
        """
    )
    session = await cur.fetchone()
    status = "active"

    if session is None:
        cur = await db.execute(
            """
            SELECT s.*, a.name as agent_name
            FROM sessions s
            LEFT JOIN agents a ON a.id = s.agent_id
            ORDER BY s.started_at DESC
            LIMIT 1
            """
        )
        session = await cur.fetchone()
        status = "completed"

    if session is None:
        return {
            "session_id": None,
            "start_time": None,
            "duration_min": None,
            "files_touched": 0,
            "agent": None,
            "red_lines": 0,
            "friction_signals": 0,
            "status": "none",
        }

    session_id = session["id"]

    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts al
        LEFT JOIN events e ON e.id = al.event_id
        WHERE al.rule_type = 'red_line' AND COALESCE(al.session_id, e.session_id) = ?
        """,
        (session_id,),
    )
    red_lines = (await cur.fetchone())["c"]

    findings = await _derive_friction_findings(db, session_id=session_id)

    cur = await db.execute(
        """
        SELECT event_type, path, detail FROM events
        WHERE session_id = ? AND event_type IN ('file_write', 'file_read', 'cred_access')
        """,
        (session_id,),
    )
    rows = await cur.fetchall()
    distinct_paths: set[str] = set()
    for row in rows:
        distinct_paths.update(_expand_file_paths(row))

    if session["ended_at"]:
        duration_min = await _minutes_between(db, session["started_at"], session["ended_at"])
    else:
        duration_min = await _minutes_between(db, session["started_at"], None)

    return {
        "session_id": session_id,
        "start_time": session["started_at"],
        "duration_min": duration_min,
        "files_touched": len(distinct_paths),
        "agent": session["agent_name"],
        "red_lines": red_lines,
        "friction_signals": len(findings),
        "status": status,
    }


async def _minutes_between(db, start: str, end: str | None) -> float | None:
    if not start:
        return None
    if end:
        cur = await db.execute("SELECT (julianday(?) - julianday(?)) * 24 * 60 as m", (end, start))
    else:
        cur = await db.execute("SELECT (julianday('now') - julianday(?)) * 24 * 60 as m", (start,))
    row = await cur.fetchone()
    return round(row["m"], 1) if row and row["m"] is not None else None


async def _get_session_history(params: dict) -> list[dict]:
    """Batched into 3 queries total regardless of n — the previous version
    issued 2 extra queries per session (events + red_line count), which at
    n=200 meant 401 sequential round-trips and was a dominant cause of this
    tool timing out under load."""
    db = await get_read_db()
    try:
        n = int(params.get("n", 5) or 5)
        n = max(1, min(n, 200))

        cur = await db.execute(
            """
            SELECT s.*, a.name as agent_name
            FROM sessions s
            LEFT JOIN agents a ON a.id = s.agent_id
            ORDER BY s.started_at DESC
            LIMIT ?
            """,
            (n,),
        )
        rows = await cur.fetchall()
        session_ids = [row["id"] for row in rows]

        if not session_ids:
            return []

        placeholders = ", ".join("?" for _ in session_ids)

        cur = await db.execute(
            f"""
            SELECT session_id, event_type, path, detail FROM events
            WHERE session_id IN ({placeholders}) AND event_type IN ('file_write', 'file_read', 'cred_access')
            """,
            session_ids,
        )
        paths_by_session: dict[str, set[str]] = {sid: set() for sid in session_ids}
        for e in await cur.fetchall():
            paths_by_session[e["session_id"]].update(_expand_file_paths(e))

        cur = await db.execute(
            f"""
            SELECT COALESCE(al.session_id, e.session_id) as sid, COUNT(*) c
            FROM alerts al
            LEFT JOIN events e ON e.id = al.event_id
            WHERE al.rule_type = 'red_line' AND COALESCE(al.session_id, e.session_id) IN ({placeholders})
            GROUP BY sid
            """,
            session_ids,
        )
        red_lines_by_session = {row["sid"]: row["c"] for row in await cur.fetchall()}

        results = []
        for row in rows:
            session_id = row["id"]
            duration_min = await _minutes_between(db, row["started_at"], row["ended_at"])

            results.append({
                "session_id": session_id,
                "date": row["started_at"],
                "duration_min": duration_min,
                "agent": row["agent_name"],
                "files_touched_count": len(paths_by_session.get(session_id, set())),
                "red_lines": red_lines_by_session.get(session_id, 0),
            })

        return results
    finally:
        await db.close()


async def _get_file_history(params: dict) -> dict:
    db = await get_db()
    filepath = params.get("filepath")
    if not filepath:
        raise ValueError("filepath is required")

    like_pattern = f"%{filepath}%"

    cur = await db.execute(
        """
        SELECT e.*, a.name as agent_name
        FROM events e
        LEFT JOIN agents a ON a.id = e.agent_id
        WHERE e.event_type IN ('file_write', 'file_read', 'cred_access')
          AND (e.path LIKE ? OR e.detail LIKE ?)
        ORDER BY e.created_at DESC
        """,
        (like_pattern, like_pattern),
    )
    rows = await cur.fetchall()

    matched_rows = []
    for row in rows:
        paths = _expand_file_paths(row)
        if any(filepath in p for p in paths):
            matched_rows.append(row)

    total_edits = sum(1 for r in matched_rows if r["event_type"] == "file_write")
    agents_involved = sorted({r["agent_name"] for r in matched_rows if r["agent_name"]})
    last_edit = matched_rows[0]["created_at"] if matched_rows else None
    sessions = sorted({r["session_id"] for r in matched_rows if r["session_id"]})

    return {
        "filepath": filepath,
        "total_edits": total_edits,
        "agents_involved": agents_involved,
        "last_edit": last_edit,
        "sessions": sessions,
    }


async def _get_red_line_events(params: dict) -> list[dict]:
    db = await get_db()
    since_hours = int(params.get("since_hours", 24) or 24)
    since_hours = max(1, min(since_hours, 24 * 365))

    cur = await db.execute(
        """
        SELECT al.id as event_id, al.rule_type, al.severity, al.description,
               al.created_at as timestamp, al.session_id as alert_session_id,
               a.process_name as process, a.name as agent_name,
               e.path as event_path, e.session_id as event_session_id
        FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        LEFT JOIN events e ON e.id = al.event_id
        WHERE al.rule_type = 'red_line'
          AND al.created_at > datetime('now', ?)
        ORDER BY al.created_at DESC
        """,
        (f"-{since_hours} hours",),
    )
    rows = await cur.fetchall()

    return [
        {
            "event_id": row["event_id"],
            "type": row["rule_type"],
            "severity": row["severity"],
            "description": row["description"],
            "timestamp": row["timestamp"],
            "process": row["process"] or row["agent_name"],
            "filepath": row["event_path"],
            "session_id": row["alert_session_id"] or row["event_session_id"],
        }
        for row in rows
    ]


async def _derive_friction_findings(db, session_id: str | None = None) -> list[dict]:
    findings: list[dict] = []

    session_clause = "AND session_id = ?" if session_id else ""
    session_params = (session_id,) if session_id else ()

    # retry_loop: same event_type called 3+ times in the same session within
    # a 10-minute window. Capped to the most recent 100 events per session
    # (unbounded scan of the whole events table was the dominant cost in
    # get_friction_findings/get_evidence_summary timing out under load).
    row_limit = "100" if session_id else "2000"
    cur = await db.execute(
        f"""
        SELECT session_id, event_type, created_at, path FROM (
            SELECT session_id, event_type, created_at, path
            FROM events
            WHERE session_id IS NOT NULL {session_clause}
            ORDER BY created_at DESC
            LIMIT {row_limit}
        )
        ORDER BY session_id, event_type, created_at
        """,
        session_params,
    )
    rows = await cur.fetchall()

    buckets: dict[tuple, list] = {}
    for row in rows:
        key = (row["session_id"], row["event_type"])
        buckets.setdefault(key, []).append(row)

    for (sid, event_type), evs in buckets.items():
        i = 0
        while i < len(evs):
            window_start = evs[i]["created_at"]
            j = i
            while j < len(evs) and _within_minutes(window_start, evs[j]["created_at"], 10):
                j += 1
            count = j - i
            if count >= 3:
                findings.append({
                    "finding_type": "retry_loop",
                    "confidence": "high" if count >= 5 else "medium",
                    "filepath": evs[i]["path"],
                    "evidence": f"{event_type} called {count} times within 10 minutes",
                    "session_id": sid,
                })
                i = j
            else:
                i += 1

    # rapid_revert: same file written twice within 60 seconds by same session.
    # Same row cap rationale as the retry_loop query above.
    cur = await db.execute(
        f"""
        SELECT session_id, event_type, created_at, path, detail FROM (
            SELECT session_id, event_type, created_at, path, detail
            FROM events
            WHERE event_type = 'file_write' AND session_id IS NOT NULL {session_clause}
            ORDER BY created_at DESC
            LIMIT {row_limit}
        )
        ORDER BY session_id, created_at
        """,
        session_params,
    )
    write_rows = await cur.fetchall()

    per_session_writes: dict[str, list] = {}
    for row in write_rows:
        per_session_writes.setdefault(row["session_id"], []).append(row)

    for sid, writes in per_session_writes.items():
        path_history: dict[str, str] = {}
        for row in writes:
            for path in _expand_file_paths(row):
                prev_ts = path_history.get(path)
                if prev_ts and _within_seconds(prev_ts, row["created_at"], 60):
                    findings.append({
                        "finding_type": "rapid_revert",
                        "confidence": "medium",
                        "filepath": path,
                        "evidence": f"written again within 60 seconds (prev write at {prev_ts})",
                        "session_id": sid,
                    })
                path_history[path] = row["created_at"]

    # session_abandoned: session older than 30 minutes with no commit event.
    cur = await db.execute(
        f"""
        SELECT id, started_at, ended_at FROM sessions
        WHERE julianday('now') - julianday(started_at) > 0.02083 {("AND id = ?" if session_id else "")}
        """,
        session_params,
    )
    old_sessions = await cur.fetchall()
    if old_sessions:
        cur = await db.execute(
            "SELECT DISTINCT session_id FROM events WHERE (event_type = 'commit' OR detail LIKE '%\"commit\"%') AND session_id IS NOT NULL"
        )
        sessions_with_commits = {row["session_id"] for row in await cur.fetchall()}
        for s in old_sessions:
            if s["id"] not in sessions_with_commits:
                findings.append({
                    "finding_type": "session_abandoned",
                    "confidence": "low",
                    "filepath": None,
                    "evidence": "session older than 30 minutes with no commit event observed",
                    "session_id": s["id"],
                })

    return findings


def _within_minutes(ts_a: str, ts_b: str, minutes: int) -> bool:
    from datetime import datetime
    try:
        a = datetime.fromisoformat(ts_a.replace(" ", "T"))
        b = datetime.fromisoformat(ts_b.replace(" ", "T"))
    except ValueError:
        return False
    return abs((b - a).total_seconds()) <= minutes * 60


def _within_seconds(ts_a: str, ts_b: str, seconds: int) -> bool:
    from datetime import datetime
    try:
        a = datetime.fromisoformat(ts_a.replace(" ", "T"))
        b = datetime.fromisoformat(ts_b.replace(" ", "T"))
    except ValueError:
        return False
    return 0 < (b - a).total_seconds() <= seconds


async def _get_friction_findings(params: dict) -> list[dict]:
    db = await get_read_db()
    try:
        session_id = params.get("session_id")
        return await _derive_friction_findings(db, session_id=session_id)
    finally:
        await db.close()


async def _get_evidence_summary(params: dict) -> dict:
    db = await get_read_db()
    try:
        days = int(params.get("days", 7) or 7)
        days = max(1, min(days, 365))

        since_clause = f"-{days} days"

        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE started_at > datetime('now', ?)",
            (since_clause,),
        )
        total_sessions = (await cur.fetchone())["c"]

        cur = await db.execute(
            """
            SELECT DISTINCT a.name FROM sessions s
            JOIN agents a ON a.id = s.agent_id
            WHERE s.started_at > datetime('now', ?)
            ORDER BY a.name
            """,
            (since_clause,),
        )
        agents_used = [r["name"] for r in await cur.fetchall()]

        cur = await db.execute(
            """
            SELECT COUNT(*) c FROM alerts
            WHERE rule_type = 'red_line' AND created_at > datetime('now', ?)
            """,
            (since_clause,),
        )
        red_lines = (await cur.fetchone())["c"]

        friction_signals = len(await _derive_friction_findings(db, session_id=None))

        # created_at is indexed (idx_events_created) and is the filter column
        # here. LIMIT caps the scan the same way _derive_friction_findings' row
        # cap does above — an unbounded scan of the whole events table for the
        # period was part of what made this handler slow to respond under load.
        cur = await db.execute(
            """
            SELECT event_type, path, detail FROM events
            WHERE event_type IN ('file_write', 'file_read', 'cred_access')
              AND created_at > datetime('now', ?)
            ORDER BY created_at DESC
            LIMIT 2000
            """,
            (since_clause,),
        )
        rows = await cur.fetchall()
        path_counts: dict[str, int] = {}
        for row in rows:
            for p in _expand_file_paths(row):
                path_counts[p] = path_counts.get(p, 0) + 1
        files_most_edited = sorted(path_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        files_most_edited = [{"filepath": p, "count": c} for p, c in files_most_edited]

        period = f"last {days} day{'s' if days != 1 else ''}"

        summary = {
            "period": period,
            "total_sessions": total_sessions,
            "agents_used": agents_used,
            "red_lines": red_lines,
            "friction_signals": friction_signals,
            "files_most_edited": files_most_edited,
        }

        evidence_hash = hashlib.sha256(json.dumps(summary, sort_keys=True).encode("utf-8")).hexdigest()
        summary["evidence_hash"] = evidence_hash

        return summary
    finally:
        await db.close()


_HANDLERS = {
    "get_current_session": _get_current_session,
    "get_session_history": _get_session_history,
    "get_file_history": _get_file_history,
    "get_red_line_events": _get_red_line_events,
    "get_friction_findings": _get_friction_findings,
    "get_evidence_summary": _get_evidence_summary,
}
