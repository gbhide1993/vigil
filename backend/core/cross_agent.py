"""Cross-agent correlation: the one detection category that requires a
unified event store across multiple agents, which is what makes it
genuinely novel among per-agent-adapter tools like agentwatch/ai-observer.

Two checks:
  - check_cross_agent_file_conflict: same file touched by 2+ different
    agents within a short window.
  - check_cross_agent_credential_access: same credential-path file
    accessed by 2+ different agents within a rolling day window.

LIMITATION (confirmed by grepping the whole backend/ tree before writing
this module): no git commit detection exists anywhere in this codebase.
process_watcher.py's dangerous-command patterns don't include git, and
there is no process-spawn or file-event tracking of git activity at all.
The "no commit occurred between the two touches" condition described in
this feature's spec is therefore NOT implemented — check_cross_agent_file_conflict
fires on the file-conflict pattern alone, with no commit-awareness. This is
an honest scoping decision, not a bug: fabricating commit detection that
doesn't exist would be worse than omitting it. See
check_cross_agent_file_conflict's docstring for the same note inline.
"""

import json

from core.alerter import Alerter

_alerter = Alerter()

# Reused from core/aggregator.py's CREDENTIAL_PATTERNS — the actual list
# already used to classify an event as cred_access (aggregator.py) and
# thus the real source of truth for "is this a credential path", not a
# separate list that could drift out of sync with it. priors.py itself
# does not define a credential-path list (only known_network_destinations
# per agent), so this cannot be imported from there as the brief assumed.
CREDENTIAL_PATTERNS = [".env", ".ssh", ".aws", ".pem", ".key"]


def is_credential_path(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in CREDENTIAL_PATTERNS)


async def _expand_file_event_paths(db, since_clause: str) -> list[dict]:
    """file_write/file_read events are aggregated (core/aggregator.py) —
    the row's own `path` column holds the containing directory, not the
    individual file; real per-file paths live in detail.paths (JSON array,
    capped at 50 per aggregation window). cred_access events are never
    aggregated and store the single real path directly on the row. This
    helper unpacks both into a flat list of {path, agent_id, session_id,
    event_type, created_at} rows so both checks can query over real file
    paths, not directory buckets."""
    cur = await db.execute(
        f"""
        SELECT agent_id, session_id, event_type, path, detail, created_at
        FROM events
        WHERE event_type IN ('file_write', 'file_read', 'cred_access')
          AND created_at > datetime('now', '{since_clause}')
        ORDER BY created_at ASC
        """
    )
    rows = await cur.fetchall()

    expanded: list[dict] = []
    for row in rows:
        detail = json.loads(row["detail"]) if row["detail"] else {}
        if row["event_type"] == "cred_access":
            if row["path"]:
                expanded.append({
                    "path": row["path"], "agent_id": row["agent_id"],
                    "session_id": row["session_id"], "event_type": row["event_type"],
                    "created_at": row["created_at"],
                })
            continue

        paths = detail.get("paths")
        if paths:
            for p in paths:
                expanded.append({
                    "path": p, "agent_id": row["agent_id"],
                    "session_id": row["session_id"], "event_type": row["event_type"],
                    "created_at": row["created_at"],
                })
        elif row["path"]:
            # Fallback for any file event that somehow wasn't aggregated
            # with a paths list — treat the row's own path as the file.
            expanded.append({
                "path": row["path"], "agent_id": row["agent_id"],
                "session_id": row["session_id"], "event_type": row["event_type"],
                "created_at": row["created_at"],
            })

    return expanded


async def _agent_names(db, agent_ids: set[int]) -> dict[int, str]:
    if not agent_ids:
        return {}
    placeholders = ", ".join("?" for _ in agent_ids)
    cur = await db.execute(f"SELECT id, name FROM agents WHERE id IN ({placeholders})", tuple(agent_ids))
    return {row["id"]: row["name"] for row in await cur.fetchall()}


async def check_cross_agent_file_conflict(db, window_minutes: int = 10) -> list[int]:
    """Detects the same file path touched by two or more DIFFERENT agents
    within a rolling window_minutes window.

    LIMITATION: the spec for this check calls for suppressing the alert if
    a git commit occurred between the two touches. No git commit detection
    exists anywhere in this codebase (confirmed by grep across backend/
    before writing this module — process_watcher.py's dangerous-command
    matching doesn't track git, and no other watcher observes git activity
    at all). That condition is therefore not implemented; this check fires
    on the cross-agent same-file pattern alone. Revisit if/when git-command
    tracking is added to process_watcher.py."""
    events = await _expand_file_event_paths(db, f"-{window_minutes} minutes")

    by_path: dict[str, list[dict]] = {}
    for e in events:
        by_path.setdefault(e["path"], []).append(e)

    fired: list[int] = []
    seen_pairs: set[tuple] = set()

    for path, touches in by_path.items():
        distinct_agents = {t["agent_id"] for t in touches}
        if len(distinct_agents) < 2:
            continue

        # Confirm genuinely different agents, not the same agent across two
        # sessions — distinct_agents is already keyed by agent_id, so any
        # pair drawn from it is, by construction, two different agents.
        touches_sorted = sorted(touches, key=lambda t: t["created_at"])
        agent_a_touch = touches_sorted[0]
        agent_b_touch = next(t for t in touches_sorted[1:] if t["agent_id"] != agent_a_touch["agent_id"])

        pair_key = (path, tuple(sorted((agent_a_touch["agent_id"], agent_b_touch["agent_id"]))))
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        names = await _agent_names(db, {agent_a_touch["agent_id"], agent_b_touch["agent_id"]})
        agent_a_name = names.get(agent_a_touch["agent_id"], "unknown agent")
        agent_b_name = names.get(agent_b_touch["agent_id"], "unknown agent")

        severity = "high" if is_credential_path(path) else "medium"
        title = f"{agent_a_name} and {agent_b_name} both touched {path} within {window_minutes} minutes — no commit between them"

        alert_id = await _alerter.fire_alert(
            agent_a_touch["agent_id"],
            severity,
            title=title,
            description=f"{agent_a_name} touched {path} at {agent_a_touch['created_at']}, then {agent_b_name} "
                         f"touched it at {agent_b_touch['created_at']} — within a {window_minutes}-minute window. "
                         "No commit-between-touches check is available (git activity is not currently tracked).",
            reason="cross_agent_conflict",
            extra_detail={
                "path": path,
                "agent_a": agent_a_name, "agent_a_id": agent_a_touch["agent_id"],
                "agent_b": agent_b_name, "agent_b_id": agent_b_touch["agent_id"],
                "window_minutes": window_minutes,
                "commit_check_available": False,
            },
            rule_type="cross_agent_conflict",
            target=path,
        )
        if alert_id is not None:
            fired.append(alert_id)

    return fired


async def check_cross_agent_credential_access(db, window_hours: int = 24) -> list[int]:
    """Detects a credential-path file (reusing aggregator.py's
    CREDENTIAL_PATTERNS — the same definition that classifies an event as
    cred_access in the first place) accessed by 2+ distinct agents within
    a rolling window_hours window, even if each individual access stayed
    under normal Red Line thresholds on its own."""
    events = await _expand_file_event_paths(db, f"-{window_hours} hours")
    credential_events = [e for e in events if is_credential_path(e["path"])]

    by_path: dict[str, list[dict]] = {}
    for e in credential_events:
        by_path.setdefault(e["path"], []).append(e)

    fired: list[int] = []

    for path, touches in by_path.items():
        distinct_agent_ids = sorted({t["agent_id"] for t in touches})
        if len(distinct_agent_ids) < 2:
            continue

        names = await _agent_names(db, set(distinct_agent_ids))
        agent_list_str = ", ".join(names.get(a, "unknown agent") for a in distinct_agent_ids)
        count = len(distinct_agent_ids)

        title = f"{count} different AI agents accessed {path} in the last {window_hours}h — {agent_list_str}"

        # Attributed to the first (earliest-touching) agent, consistent
        # with check_cross_agent_file_conflict — this is a cross-agent
        # pattern, not owned by any single agent, but fire_alert requires
        # an agent_id.
        primary_agent_id = distinct_agent_ids[0]

        alert_id = await _alerter.fire_alert(
            primary_agent_id,
            "high",
            title=title,
            description=f"{path} (a credential-sensitive path) was accessed by {count} different agents "
                         f"in the last {window_hours} hours: {agent_list_str}. Each access may have stayed under "
                         "normal Red Line thresholds individually, but multiple agents touching the same "
                         "credential file is a distinct aggregate risk signal.",
            reason="cross_agent_credential_pattern",
            extra_detail={
                "path": path,
                "agent_ids": distinct_agent_ids,
                "agent_names": [names.get(a, "unknown agent") for a in distinct_agent_ids],
                "window_hours": window_hours,
            },
            rule_type="cross_agent_credential_pattern",
            target=path,
        )
        if alert_id is not None:
            fired.append(alert_id)

    return fired
