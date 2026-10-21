"""Read-only query layer for the MCP server (api/mcp_routes.py). Every
function here only SELECTs from tables that watchers/aggregator already
populate — no new data collection, no writes, nothing that touches network.
"""

import hashlib
import json
import re

from core.activity_filter import is_generated_path
from core.sessions import has_activity_exists_sql, is_idle, last_activity_by_open_session, session_visible_sql
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

    # A resumed session with no real activity (Vigil only found the agent already running at startup, and
    # nothing happened after) is not a current session: it is skipped here, not reported as active.
    # core.sessions.session_visible_sql is the one definition of that.
    cur = await db.execute(
        f"""
        SELECT s.*, a.name as agent_name, {has_activity_exists_sql('s')} AS has_activity
        FROM sessions s
        LEFT JOIN agents a ON a.id = s.agent_id
        WHERE s.ended_at IS NULL AND {session_visible_sql('s')}
        ORDER BY s.started_at DESC
        LIMIT 1
        """
    )
    session = await cur.fetchone()
    status = "active"

    if session is None:
        cur = await db.execute(
            f"""
            SELECT s.*, a.name as agent_name, {has_activity_exists_sql('s')} AS has_activity
            FROM sessions s
            LEFT JOIN agents a ON a.id = s.agent_id
            WHERE {session_visible_sql('s')}
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
            "resumed": False,
            "has_activity": False,
            "last_activity_at": None,
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

    # The idle sweep is off, so an open session never closes by itself. Display rule only (nothing is written):
    # no event for longer than the idle timeout means "idle", not "active".
    last_activity_at = None
    if status == "active":
        last_activity_at = (await last_activity_by_open_session(db, session_id)).get(session_id) or session["started_at"]
        if is_idle(last_activity_at):
            status = "idle"

    return {
        "session_id": session_id,
        "start_time": session["started_at"],
        "last_activity_at": last_activity_at,
        "duration_min": duration_min,
        "files_touched": len(distinct_paths),
        "agent": session["agent_name"],
        "red_lines": red_lines,
        "friction_signals": len(findings),
        "resumed": bool(session["resumed"]),
        "has_activity": bool(session["has_activity"]),
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


# ---------------------------------------------------------------- friction findings: retry_loop settings
# retry_loop means "the same thing, repeated, in a short time". The thresholds are judgment calls, not measured
# values: they are set so ordinary work (one save and its formatter, one git command and its console host)
# does not reach them, and they can be changed here without touching anything else.
RETRY_WINDOW_MINUTES = 10
RETRY_THRESHOLD_FILE_WRITE = 5      # the same file written 5+ times in the window
RETRY_THRESHOLD_PROC_SPAWN = 3      # the same executable with the same command line spawned 3+ times in the window
RETRY_THRESHOLDS = {"file_write": RETRY_THRESHOLD_FILE_WRITE, "proc_spawn": RETRY_THRESHOLD_PROC_SPAWN}
# "high" at twice the threshold, otherwise "medium".
RETRY_HIGH_MULTIPLIER = 2

# Processes that are plumbing, not something the agent chose to run again. Skipped by retry_loop. Found by
# listing the executables in the recorded proc_spawn events. Not HELPER_PROCESS_NAMES (core/activity_filter.py):
# that set also holds agent names (claude, codex), and the same agent command repeated is still worth reporting.
FRICTION_IGNORED_PROCESSES = frozenset({
    "conhost",       # console host: Windows starts one for every console program, so it appears next to every command
    "git",           # git runs several child git.exe per command, and editors poll it (git status) on a timer
    "cmd", "powershell", "pwsh", "bash", "sh",   # shells that wrap every command an agent runs
    "wsl", "wslhost",                            # WSL launchers
    "werfault",                                  # Windows error reporting
    "tasklist", "taskkill", "reg", "chcp", "where",   # one-shot Windows helpers called by tools and scripts
    "codex-windows-sandbox-service",             # the Codex sandbox helper
    "onedrive.sync.service",                     # OneDrive
    "vigil-backend", "vlaw-backend", "vigil",    # Vigil's own processes
})

# Paths that are an agent tool's own bookkeeping, not work on the user's files. Compared lower-case with forward
# slashes. Skipped by retry_loop.
FRICTION_IGNORED_PATH_PARTS = (
    "/.claude/file-history/",      # Claude Code checkpoint copies: one new file per edit, written in bursts of 100+
    "shell-snapshots",             # Claude Code shell snapshot scripts
    "/appdata/local/temp/",        # temp files of any tool
    "/windows/temp/",
    "/systemprofile/",             # the SYSTEM account's profile: services writing their own state
    # Build output the shared generated-path check (core/activity_filter.is_generated_path, used below) does not know:
    # it covers dist, build, node_modules, .venv, caches and .git, but not these.
    "/out/",                       # compiler output folders (for example vigil-vscode/out)
    "/win-unpacked/",              # electron-builder output; also under dist/, listed for other output folders
    # Editor and tool temp names:
    ".tmp.",                       # atomic-save temp files such as main.js.tmp.20932.2518734f0f79
    ".timestamp-",                 # Vite's temporary config copies, vite.config.js.timestamp-<n>-<hash>.mjs
    "~$",                          # Microsoft Office lock files, ~$document.docx
    ".swp",                        # vim swap files
)
_CLAUDE_CWD_MARKER = re.compile(r"claude-[0-9a-f]+-cwd")   # Claude Code's working-directory marker files

# session_abandoned ("older than 30 minutes with no commit event") is switched off: Vigil does not record commit
# events, so the rule fired for almost every session (1,087 of 1,190 findings in one real database). The code stays
# so it can come back when commits are recorded.
EMIT_SESSION_ABANDONED = False


# The SQL side of the same exclusions, shared by retry_loop and rapid_revert: Vigil's own footprint, and the cache
# and snapshot paths (so they cannot crowd real events out of the row cap). The Python side is
# FRICTION_IGNORED_PATH_PARTS / _is_ignored_friction_path above.
_FRICTION_SQL_PATH_FILTER = """(path IS NULL OR (
                    path NOT LIKE '%vigil-backend.exe%'
                    AND path NOT LIKE '%\\Vigil\\tray\\Vigil.exe%'
                    AND path NOT LIKE '%\\Vigil\\backend\\%'
                    AND path NOT LIKE '%\\Vigil\\tray\\%'
                    AND path NOT LIKE '%\\V-LAW\\%'
                    AND path NOT LIKE '%file-history%'
                    AND path NOT LIKE '%shell-snapshots%'
              ))"""


def _norm_path(path: str | None) -> str:
    return (path or "").replace("\\", "/").lower()


def _is_ignored_friction_path(path: str | None) -> bool:
    """Not work on the user's files: an agent tool's bookkeeping, a temp file, or generated output. Generated
    folders come from core.activity_filter.is_generated_path (not repeated here)."""
    low = _norm_path(path)
    return (
        any(part in low for part in FRICTION_IGNORED_PATH_PARTS)
        or bool(_CLAUDE_CWD_MARKER.search(low))
        or is_generated_path(path)
    )


def _executable_stem(path: str | None) -> str:
    """"C:\\Windows\\system32\\cmd.exe /d /s /c npx" -> "cmd"; "git.exe" -> "git"."""
    match = re.search(r"([A-Za-z0-9_.\-]+)\.exe", path or "", re.IGNORECASE)
    if match:
        return match.group(1).lower()
    first = (path or "").strip().split(" ")[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return re.sub(r"\.(exe|com|bin)$", "", first)


def _command_key(row) -> str:
    """The thing that repeated: for a process, the executable and its command line (the path column holds the
    full command line when one was captured; the stored args are added when they are not already in it)."""
    path = row["path"] or ""
    try:
        args = json.loads(row["detail"] or "{}").get("args") or []
    except ValueError:
        args = []
    extra = " ".join(str(a) for a in args)
    return path if not extra or extra in path else f"{path} {extra}"


async def _derive_friction_findings(db, session_id: str | None = None) -> list[dict]:
    findings: list[dict] = []

    session_clause = "AND session_id = ?" if session_id else ""
    session_params = (session_id,) if session_id else ()

    # retry_loop: the same file written, or the same command spawned, again and again in a short window, in one
    # session. Grouped by (session, event type, path) and for processes by executable plus command line, so three
    # different files or three different commands are not a loop. Only file_write and proc_spawn are considered
    # (a repeated connection to one destination is normal keep-alive traffic and the network and MCP watchers are
    # off). Thresholds and exclusions are the constants above. Capped to the most recent events (an unbounded scan of
    # the whole events table was the dominant cost in get_friction_findings/get_evidence_summary timing out under
    # load); the cache paths are left out in SQL as well so they cannot crowd the real events out of the cap.
    #
    # Vigil's own footprint is excluded so installing, debugging, or rebuilding Vigil itself doesn't get flagged
    # as agent friction: our own backend repeatedly spawning (vigil-backend.exe) and our own tray repeatedly
    # touching its own Electron install tree are not an agent retry loop.
    row_limit = "100" if session_id else "2000"
    cur = await db.execute(
        f"""
        SELECT session_id, event_type, created_at, path, detail FROM (
            SELECT session_id, event_type, created_at, path, detail
            FROM events
            WHERE session_id IS NOT NULL {session_clause}
              AND event_type IN ('file_write', 'proc_spawn')
              AND {_FRICTION_SQL_PATH_FILTER}
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
        if not row["path"]:
            continue
        if row["event_type"] == "proc_spawn":
            if _executable_stem(row["path"]) in FRICTION_IGNORED_PROCESSES:
                continue
            what = _command_key(row)
        else:
            if _is_ignored_friction_path(row["path"]):
                continue
            what = row["path"]
        buckets.setdefault((row["session_id"], row["event_type"], what), []).append(row)

    for (sid, event_type, what), evs in buckets.items():
        threshold = RETRY_THRESHOLDS[event_type]
        i = 0
        while i < len(evs):
            window_start = evs[i]["created_at"]
            j = i
            while j < len(evs) and _within_minutes(window_start, evs[j]["created_at"], RETRY_WINDOW_MINUTES):
                j += 1
            count = j - i
            if count >= threshold:
                shown = what if len(what) <= 120 else what[:117] + "..."
                findings.append({
                    "finding_type": "retry_loop",
                    "confidence": "high" if count >= RETRY_HIGH_MULTIPLIER * threshold else "medium",
                    "filepath": evs[i]["path"],
                    "evidence": f"{shown} {event_type} {count} times within {RETRY_WINDOW_MINUTES} minutes",
                    "session_id": sid,
                })
                i = j
            else:
                i += 1

    # rapid_revert: same file written twice within 60 seconds by same session. The rule is unchanged except that
    # the cache, temp, shell-snapshot and claude-*-cwd paths are skipped (the same exclusions as retry_loop): Claude
    # Code writes every checkpoint file twice in quick succession, which is not a revert.
    # Same row cap rationale as the retry_loop query above.
    cur = await db.execute(
        f"""
        SELECT session_id, event_type, created_at, path, detail FROM (
            SELECT session_id, event_type, created_at, path, detail
            FROM events
            WHERE event_type = 'file_write' AND session_id IS NOT NULL {session_clause}
              AND {_FRICTION_SQL_PATH_FILTER}
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
                if _is_ignored_friction_path(path):
                    continue
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

    # session_abandoned: session older than 30 minutes with no commit event. Switched off (EMIT_SESSION_ABANDONED):
    # Vigil does not record commit events, so every old session matched.
    if EMIT_SESSION_ABANDONED:
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
