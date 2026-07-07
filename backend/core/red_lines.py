"""Red Line rules: a hardcoded, non-disableable safety floor.

Unlike the policy-driven checks in alerter.py (credential_paths,
scope_directories, approved_mcp_servers, ...), these six rules are not
read from policy and cannot be turned off from the UI or the policy
file. They exist so that even a misconfigured or wide-open policy
still catches the handful of things V-LAW considers never acceptable.

Callers (watchers / aggregator) run RedLines checks BEFORE their own
policy-based checks for the same event. Each rule fires at most once
per RED_LINE_WINDOW_SECONDS per agent; activity in between is counted
and folded into the next alert's message as a batch summary, e.g.
"3 more SSH access events in the last minute" — this keeps a busy
agent from flooding the alerts view while still surfacing everything.
"""

import os
import re
import time
from pathlib import Path

from core.alerter import Alerter

RED_LINE_WINDOW_SECONDS = 60

SSH_DIR_PATTERN = re.compile(r"[\\/]\.ssh[\\/]", re.IGNORECASE)

CLAUDE_CACHE_PATTERN = re.compile(
    r"\.claude[\\/]file-history", re.IGNORECASE
)

APPROVED_NETWORK_DESTINATIONS = {
    "api.anthropic.com",
    "api.openai.com",
    "api.github.com",
    "marketplace.cursor.sh",
    "cursor.sh",
    "copilot.microsoft.com",
    "objects.githubusercontent.com",
    "127.0.0.1",
    "localhost",
}

DANGEROUS_COMMAND_PATTERNS = [
    "curl", "wget", "nc", "ncat", "ssh", "scp",
    "python -c", "python3 -c", "powershell -enc", "powershell -command",
]

# Session launch directory: the working directory V-LAW itself was
# started from. Used as the reference point for "outside the active
# workspace" (RED LINE 2) and "a different project" (RED LINE 6) —
# there is no other notion of "the current project" available to the
# backend, since scope_directories is a separate, user-editable policy
# concept and must not be relied on for a floor rule.
SESSION_LAUNCH_DIR = Path.cwd().resolve()


def is_ssh_path(path: str) -> bool:
    return bool(SSH_DIR_PATTERN.search(path))


def _is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def is_env_outside_workspace(path: str) -> bool:
    if os.path.basename(path) != ".env":
        return False
    try:
        directory = Path(path).resolve().parent
    except (OSError, ValueError):
        return False
    return not _is_relative_to(directory, SESSION_LAUNCH_DIR)


def is_claude_cache_write(path: str) -> bool:
    return bool(CLAUDE_CACHE_PATTERN.search(path))


def is_unknown_destination(dest: str) -> bool:
    return dest not in APPROVED_NETWORK_DESTINATIONS


def is_dangerous_command(cmdline: str) -> str | None:
    """Returns the matched pattern, or None if the command is clean."""
    lowered = cmdline.lower()
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern in lowered:
            return pattern
    return None


def _find_git_root(path: Path) -> Path | None:
    for candidate in [path] + list(path.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def is_cross_project_read(path: str) -> bool:
    try:
        directory = Path(path).resolve().parent
    except (OSError, ValueError):
        return False

    file_git_root = _find_git_root(directory)
    if file_git_root is None:
        return False

    session_git_root = _find_git_root(SESSION_LAUNCH_DIR)
    return session_git_root is not None and file_git_root != session_git_root


class RedLines:
    """Fires the six Red Line rules and batches repeats within a 60s
    window per (agent_id, rule) so a noisy agent can't flood alerts."""

    def __init__(self):
        self.alerter = Alerter()
        # (agent_id, rule_key) -> {"last_fired": float, "batched": int}
        self._state: dict[tuple, dict] = {}

    async def _fire(self, agent_id: int, rule_key: str, severity: str, title: str, description: str, extra_detail: dict) -> None:
        now = time.time()
        state = self._state.get((agent_id, rule_key))

        if state is not None and now - state["last_fired"] < RED_LINE_WINDOW_SECONDS:
            state["batched"] += 1
            return

        if state is not None and state["batched"] > 0:
            description = f"{description} ({state['batched']} more {rule_key.replace('_', ' ')} events in the last minute)"

        self._state[(agent_id, rule_key)] = {"last_fired": now, "batched": 0}

        await self.alerter.fire_alert(
            agent_id,
            severity,
            title=title,
            description=description,
            reason=f"red_line_{rule_key}",
            extra_detail=extra_detail,
            rule_type="red_line",
        )

    async def check_ssh_access(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_ssh_path(path):
            return
        await self._fire(
            agent_id, "ssh_access", "high",
            title=f"RED LINE: SSH directory accessed by {agent_name}",
            description=f"{agent_name} accessed your SSH directory. This is unusual and worth reviewing.",
            extra_detail={"path": path},
        )

    async def check_env_outside_workspace(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_env_outside_workspace(path):
            return
        await self._fire(
            agent_id, "env_outside_workspace", "high",
            title=f"RED LINE: environment file read outside workspace by {agent_name}",
            description=f"{agent_name} read an environment file outside your active project.",
            extra_detail={"path": path},
        )

    async def check_claude_cache_write(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_claude_cache_write(path):
            return
        await self._fire(
            agent_id, "claude_cache_write", "high",
            title=f"RED LINE: hidden cache write by {agent_name}",
            description=f"{agent_name} wrote to Claude's hidden cache directory. This may include credential file copies.",
            extra_detail={"path": path},
        )

    async def check_unknown_destination(self, agent_id: int, agent_name: str, destination: str) -> None:
        if not is_unknown_destination(destination):
            return
        await self._fire(
            agent_id, "unknown_destination", "low",
            title=f"RED LINE: unrecognised network destination for {agent_name}",
            description=f"{agent_name} connected to an unrecognised destination: {destination}",
            extra_detail={"destination": destination},
        )

    async def check_dangerous_command(self, agent_id: int, agent_name: str, cmdline: str) -> None:
        matched = is_dangerous_command(cmdline)
        if matched is None:
            return
        await self._fire(
            agent_id, "dangerous_command", "medium",
            title=f"RED LINE: sensitive command spawned by {agent_name}",
            description=f"{agent_name} spawned a potentially sensitive command: {cmdline}",
            extra_detail={"command": cmdline, "matched_pattern": matched},
        )

    async def check_cross_project_read(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_cross_project_read(path):
            return
        await self._fire(
            agent_id, "cross_project_read", "medium",
            title=f"RED LINE: cross-project file read by {agent_name}",
            description=f"{agent_name} read files from a different project directory than the active workspace.",
            extra_detail={"path": path},
        )
