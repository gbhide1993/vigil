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
"""

import json

FILE_EVENT_TYPES = ("file_write", "file_delete", "file_read", "file_create", "cred_access")


def attribution_for(agent_name: str | None, event_source: str | None, confidence: str | None) -> dict:
    agent = agent_name or "unknown agent"
    exact = event_source == "etw"
    if exact:
        label = f"by {agent}"
    else:
        label = f"attributed to {agent} (best guess)"
    return {
        "attribution": "exact" if exact else "best_guess",
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
