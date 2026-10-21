"""How a file event is described to the user.

Only the ETW tier knows which process made a change (the kernel trace names
the process that performed the operation), so only ETW-sourced events are
shown with plain wording. The native and polling observers learn that a file
changed, not who changed it: the event is given to whichever recognised agent
was running (see watchers/file_watcher.py::_find_owning_agent_pid). A change
you make yourself while an agent is running looks the same, so those events
are always labelled "attributed to <agent> (best guess)" together with the
stored confidence ("low": more than one agent was running; "medium": one
agent was running, writer not verified).

One exception, by file location: a change under the user's ~/.claude folder is Claude Code's own bookkeeping
(its checkpoint files), and one under ~/.codex is Codex's. Such a change is given to that agent when it is running,
whatever else is running, and is labelled "attributed to <agent> by file location" (event_source "path",
confidence "medium"). The location says whose folder it is; it does not name the process that wrote the file, so it
is not shown as exact.
"""

import json
import os

FILE_EVENT_TYPES = ("file_write", "file_delete", "file_read", "file_create", "cred_access")

# Folders under the user's home that belong to one agent: (folder name, agent key as in core.attributor.KNOWN_AGENTS).
PATH_AGENT_FOLDERS = ((".claude", "claude_code"), (".codex", "codex"))


def agent_for_path(path: str | None, home: str | None = None) -> str | None:
    """The agent whose own folder this path is in (~/.claude -> claude_code, ~/.codex -> codex), or None.
    Case-insensitive; backslashes and slashes are the same. Only these two folders under the home folder count."""
    if not path:
        return None
    norm = path.replace("\\", "/").lower().rstrip("/")
    home_norm = (home if home is not None else os.path.expanduser("~")).replace("\\", "/").lower().rstrip("/")
    if not home_norm:
        return None
    for folder, agent in PATH_AGENT_FOLDERS:
        root = f"{home_norm}/{folder}"
        if norm == root or norm.startswith(root + "/"):
            return agent
    return None


def attribution_for(agent_name: str | None, event_source: str | None, confidence: str | None) -> dict:
    agent = agent_name or "unknown agent"
    exact = event_source == "etw"
    by_path = event_source == "path"
    if exact:
        label = f"by {agent}"
    elif by_path:
        label = f"attributed to {agent} by file location"
    else:
        label = f"attributed to {agent} (best guess)"
    return {
        "attribution": "exact" if exact else ("path" if by_path else "best_guess"),
        "attribution_confidence": confidence,
        "attribution_label": label if confidence is None or exact else f"{label}, confidence {confidence}",
    }


def parse_detail(raw) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def event_attribution(row: dict) -> dict:
    """Attribution fields for one events row (dict with agent_name,
    event_source, detail); {} for events that are not file events."""
    if row.get("event_type") not in FILE_EVENT_TYPES:
        return {}
    detail = parse_detail(row.get("detail"))
    fields = attribution_for(row.get("agent_name"), row.get("event_source"), detail.get("attribution_confidence"))
    fields["change"] = detail.get("change")
    return fields
