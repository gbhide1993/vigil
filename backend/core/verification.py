"""Session verification: compares what an agent's own session log claims
it did against what V-LAW independently observed at the OS level for the
same session. This is the core differentiator — OS-level truth vs agent
self-report — so a mismatch here is a stronger signal than any single
anomaly rule.

Only claude_code is supported today: its session logs are the only
self-report format this module knows how to parse (~/.claude/projects/
<sanitized-cwd>/<session-id>.jsonl, confirmed against a real log on this
machine — see below). No assumption is made about cursor/copilot session
log formats; get_installed_agent_version()-style "return None, don't guess"
applies here too.
"""

import json
import os
import re
from pathlib import Path

from db.database import get_db

# File-path-bearing tool names in a Claude Code .jsonl transcript, and
# which of their `input` keys hold the path(s) touched. Confirmed against
# a real transcript (~/.claude/projects/.../<session>.jsonl) on 2026-07-14:
# entries are newline-delimited JSON, one per line; assistant turns carry
# tool_use blocks under message.content[], each with `name` and `input`.
READ_TOOLS = {"Read": ["file_path"], "Glob": []}
WRITE_TOOLS = {"Write": ["file_path"], "Edit": ["file_path"], "NotebookEdit": ["notebook_path"]}


def _claude_projects_dir() -> Path:
    return Path(os.path.expanduser("~/.claude/projects"))


def _sanitize_cwd_to_project_dirname(cwd: str) -> str:
    """Mirrors Claude Code's own sanitization of a working directory into
    its projects/ subdirectory name: drive-letter colon and all path
    separators become '-'. Confirmed against this machine's real
    ~/.claude/projects/ listing, e.g. C:\\Users\\gbhid\\vlaw ->
    c--Users-gbhid-vlaw."""
    normalized = cwd.replace("\\", "/")
    return re.sub(r"[:/]", "-", normalized).lower()


def find_session_log_path(session_id: str, project_cwd: str) -> Path | None:
    """Locates the .jsonl transcript for a given Claude Code session_id.
    project_cwd should be the directory the agent was launched from
    (core.red_lines.SESSION_LAUNCH_DIR is V-LAW's own notion of this).
    Returns None if no matching file exists — never guesses a path."""
    projects_dir = _claude_projects_dir()
    if not projects_dir.is_dir():
        return None

    project_dirname = _sanitize_cwd_to_project_dirname(project_cwd)
    candidate = projects_dir / project_dirname / f"{session_id}.jsonl"
    if candidate.is_file():
        return candidate

    # Fallback: the sanitization rule is reverse-engineered from observed
    # output, not documented — if it doesn't match, search all project dirs
    # for this session_id rather than silently failing.
    for entry in projects_dir.iterdir():
        if not entry.is_dir():
            continue
        match = entry / f"{session_id}.jsonl"
        if match.is_file():
            return match
    return None


def parse_agent_claimed_files(log_path: Path) -> dict[str, set[str]]:
    """Parses a Claude Code .jsonl transcript and returns
    {"read": {paths...}, "write": {paths...}}, normalized (forward slashes,
    lowercase drive letter) so they can be compared against OS-observed
    paths regardless of which slash style a given tool call used."""
    reads: set[str] = set()
    writes: set[str] = set()

    with open(log_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # transcript can contain partial/corrupt trailing lines mid-write

            if entry.get("type") != "assistant":
                continue
            message = entry.get("message") or {}
            content = message.get("content")
            if not isinstance(content, list):
                continue

            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                name = block.get("name")
                tool_input = block.get("input") or {}

                if name in READ_TOOLS:
                    for key in READ_TOOLS[name]:
                        path = tool_input.get(key)
                        if path:
                            reads.add(_normalize_path(path))
                elif name in WRITE_TOOLS:
                    for key in WRITE_TOOLS[name]:
                        path = tool_input.get(key)
                        if path:
                            writes.add(_normalize_path(path))

    return {"read": reads, "write": writes}


def _normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized[0].lower() + normalized[1:]
    return normalized


async def get_os_observed_files(session_id: str, db) -> dict[str, set[str]]:
    """Queries V-LAW's own events table for file_read/file_write events
    on this session_id. File events are aggregated (core/aggregator.py) —
    individual paths live in detail.paths (capped at 50 per aggregation
    window), not the row's own `path` column, which holds the containing
    directory instead."""
    cur = await db.execute(
        "SELECT event_type, path, detail FROM events WHERE session_id = ? AND event_type IN ('file_read', 'file_write', 'cred_access')",
        (session_id,),
    )
    rows = await cur.fetchall()

    reads: set[str] = set()
    writes: set[str] = set()

    for row in rows:
        detail = json.loads(row["detail"]) if row["detail"] else {}
        paths = detail.get("paths")
        bucket = writes if row["event_type"] in ("file_write",) else reads
        if row["event_type"] == "cred_access":
            # cred_access events store the single real path directly on
            # the row (core/aggregator.py::_write_credential_event), and
            # the underlying access could be either a read or a write —
            # detail.event_type carries which.
            bucket = writes if detail.get("event_type") == "file_write" else reads
            bucket.add(_normalize_path(row["path"]))
            continue
        if paths:
            for p in paths:
                bucket.add(_normalize_path(p))
        elif row["path"]:
            bucket.add(_normalize_path(row["path"]))

    return {"read": reads, "write": writes}


CREDENTIAL_MARKERS = (".ssh", ".aws", ".env", ".pem", ".key")


def touches_credential_path(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in CREDENTIAL_MARKERS)


async def build_verification_report(session_id: str, agent_name: str, db) -> dict:
    """Compares Vigil's OS-level captured events against the agent's own
    self-reported session log. Returns a dict shaped for the
    GET /sessions/{session_id}/verify endpoint; see module docstring."""
    if agent_name != "claude_code":
        return {
            "session_id": session_id,
            "supported": False,
            "reason": f"session log parsing is only implemented for claude_code, not {agent_name}",
        }

    cur = await db.execute("SELECT started_at FROM sessions WHERE id = ?", (session_id,))
    session_row = await cur.fetchone()
    project_cwd = os.getcwd()  # VLAW_HOST_ROOT/session-launch-dir equivalent; see core.red_lines.SESSION_LAUNCH_DIR

    log_path = find_session_log_path(session_id, project_cwd)
    if log_path is None:
        return {
            "session_id": session_id,
            "supported": True,
            "log_found": False,
            "reason": "no matching claude_code session transcript found under ~/.claude/projects/",
        }

    agent_claimed = parse_agent_claimed_files(log_path)
    os_observed = await get_os_observed_files(session_id, db)

    agent_all = agent_claimed["read"] | agent_claimed["write"]
    os_all = os_observed["read"] | os_observed["write"]

    os_only = os_all - agent_all
    agent_only = agent_all - os_all
    overlap = agent_all & os_all

    discrepancies = [
        {"path": path, "seen_by": "os_only"} for path in sorted(os_only)
    ] + [
        {"path": path, "seen_by": "agent_only"} for path in sorted(agent_only)
    ]

    union_size = len(agent_all | os_all)
    match_rate = round(len(overlap) / union_size * 100, 1) if union_size else 100.0

    return {
        "session_id": session_id,
        "supported": True,
        "log_found": True,
        "log_path": str(log_path),
        "agent_reported_count": len(agent_all),
        "os_observed_count": len(os_all),
        "discrepancies": discrepancies,
        "match_rate": match_rate,
    }
