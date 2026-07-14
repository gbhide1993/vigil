"""Red Line rules: a hardcoded, non-disableable safety floor.

Unlike the policy-driven checks in alerter.py (credential_paths,
scope_directories, approved_mcp_servers, ...), these rules are not
read from policy and cannot be turned off from the UI or the policy
file. They exist so that even a misconfigured or wide-open policy
still catches the handful of things V-LAW considers never acceptable.

Callers (watchers / aggregator) run RedLines checks BEFORE their own
policy-based checks for the same event. Each rule fires at most once
per RED_LINE_WINDOW_SECONDS per agent; activity in between is counted
and folded into the next alert's message as a batch summary, e.g.
"3 more SSH access events in the last minute" — this keeps a busy
agent from flooding the alerts view while still surfacing everything.

RL7/RL7b (env var redirect, malicious config execution) were added for
CVE-2026-21852 / CVE-2025-59536 class attacks — see check_env_var_redirect
and check_malicious_config_execution below. RL8 (MCP auto-approval) extends
RL7's CVE-2026-21852 coverage to the MCP-server attack surface disclosed by
Check Point Research — see check_mcp_auto_approval below.
"""

import os
import re
import time
from pathlib import Path

from core.alerter import Alerter
from core.priors import get_prior

RED_LINE_WINDOW_SECONDS = 60  # default, overridden per-rule in RED_LINE_WINDOWS

RED_LINE_WINDOWS = {
    "ssh_access":            300,   # 5 min — SSH access is rare, keep tight
    "env_outside_workspace": 300,
    "claude_cache_write":    300,   # genuinely anomalous tier — no active session
    "checkpoint_activity":   300,   # normal /rewind tier — dismissible, not a Red Line
    "unknown_destination":   600,   # network polling can fire constantly
    "dangerous_command":     600,   # curl/wget in loops
    "cross_project_read":    300,
    "env_redirect":          300,   # CVE-2026-21852 pattern
    "config_exec":           300,   # CVE-2025-59536 pattern
    "mcp_autoapproval":      300,   # CVE-2026-21852 pattern (MCP attack surface)
}

# RL3: how long after a session's ended_at a hidden-cache write is still
# considered "correlated with an active session" rather than anomalous —
# checkpoint writes can lag slightly behind the session-close tick
# (SessionManager.close_idle_sessions runs on a 60s scheduler interval, see
# core/sessions.py), so a strict "must be exactly open" check would
# misclassify writes that land in that gap as anomalous.
CLAUDE_CACHE_SESSION_GRACE_SECONDS = 60

# Env vars whose value is expected to point at the agent's own official API
# host. Keyed by the var name; checked against AGENT_PRIORS[agent]["known_network_destinations"]
# (core/priors.py) as the source of truth for "official host" per agent.
AGENT_CONFIG_ENV_VARS = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "OPENAI_API_KEY",
}
# Vars whose value is a URL (host redirect target) vs an opaque credential —
# only URL-valued vars can be checked against a known-host allowlist. A
# credential var (*_API_KEY) being merely *set* isn't itself a redirect
# signal, so it's captured for audit context but doesn't independently fire.
ENV_URL_VARS = {"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"}

# Config files whose write is considered "agent-relevant" for RL7b. Matched
# against the basename/suffix of the written path.
AGENT_CONFIG_FILENAMES = {".claude/settings.json", ".cursor/config", ".vscode/settings.json"}
CONFIG_EXEC_WINDOW_SECONDS = 2       # brief's "within 2 seconds" correlation window
CONFIG_EXEC_SESSION_THRESHOLD = 3    # "fewer than 3 prior approved sessions"

# RL8: project-scoped MCP server config. A write here followed by an MCP
# connection within MCP_AUTOAPPROVAL_WINDOW_SECONDS is a candidate for
# auto-approval — see check_mcp_auto_approval below.
MCP_CONFIG_FILENAME = ".mcp.json"
MCP_AUTOAPPROVAL_WINDOW_SECONDS = CONFIG_EXEC_WINDOW_SECONDS  # reuse RL7b's window, per brief
MCP_AUTOAPPROVAL_SESSION_THRESHOLD = 3  # "one of the first 3 sessions for this project directory"

SSH_DIR_PATTERN = re.compile(r"[\\/]\.ssh[\\/]", re.IGNORECASE)

CLAUDE_CACHE_PATTERN = re.compile(
    r"\.claude[\\/]file-history", re.IGNORECASE
)

APPROVED_NETWORK_DESTINATIONS = {
    "api.anthropic.com",
    "statsig.anthropic.com",
    "sentry.io",
    "api.openai.com",
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "update.googleapis.com",
    "clients2.google.com",
    "marketplace.cursor.sh",
    "marketplace.cursorapi.com",
    "api2.cursor.sh",
    "cursor.sh",
    "extensions.vscode.dev",
    "copilot.microsoft.com",
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    "githubcopilot.com",
    "vscode.blob.core.windows.net",
    "objects.githubusercontent.com",
    "127.0.0.1",
    "localhost",
}

# Matched against the executable's basename, never the full argv blob — a
# bare substring check against the whole cmdline false-positives constantly
# (e.g. "nc" inside "sync", "function", "--renderer-client-id", which every
# Electron subprocess spawn includes as ordinary flag text).
DANGEROUS_EXE_PATTERNS = {"curl", "wget", "nc", "ncat", "ssh", "scp"}
DANGEROUS_INLINE_PATTERNS = ["python -c", "python3 -c", "powershell -enc", "powershell -command"]

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


async def has_active_or_recent_session(agent_id: int, db) -> bool:
    """RL3 tiering: does agent_id have a session that's currently open
    (ended_at IS NULL) or closed within the last
    CLAUDE_CACHE_SESSION_GRACE_SECONDS? Used to distinguish normal
    checkpoint activity (write correlates with an active session) from a
    genuinely anomalous cache write (no session in progress at all).

    NOTE: this correlates on session *existence*, not on matching the
    specific UUID subfolder under ~/.claude/file-history/ against a
    specific row in the sessions table — Claude Code's own internal
    checkpoint-folder UUIDs and V-LAW's session UUIDs (core/sessions.py,
    SessionManager.touch: uuid.uuid4() per V-LAW-observed session) are two
    independent ID spaces with no known mapping between them, so a literal
    string match would be fabricated, not a real signal. "Does this agent
    have any active/recent session" is the honest, available proxy."""
    cur = await db.execute(
        """
        SELECT 1 FROM sessions
        WHERE agent_id = ?
          AND (ended_at IS NULL OR ended_at > datetime('now', ? || ' seconds'))
        LIMIT 1
        """,
        (agent_id, f"-{CLAUDE_CACHE_SESSION_GRACE_SECONDS}"),
    )
    return await cur.fetchone() is not None


def is_unknown_destination(dest: str) -> bool:
    return dest not in APPROVED_NETWORK_DESTINATIONS


def is_dangerous_command(cmdline: str, exe_basename: str = "") -> str | None:
    """Returns the matched pattern, or None if the command is clean."""
    exe = re.sub(r"\.(exe|bin)$", "", exe_basename.lower())
    if exe in DANGEROUS_EXE_PATTERNS:
        return exe
    lowered = cmdline.lower()
    for pattern in DANGEROUS_INLINE_PATTERNS:
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


def is_env_var_redirect(agent_name: str, var_name: str, value: str) -> bool:
    """RL7 (CVE-2026-21852 pattern): does this agent-config env var point
    somewhere other than the agent's known official API host? Only
    URL-valued vars (ANTHROPIC_BASE_URL, OPENAI_BASE_URL) are checked —
    *_API_KEY vars are opaque credentials, not redirect targets."""
    if var_name.upper() not in ENV_URL_VARS or not value:
        return False

    prior = get_prior(agent_name)
    known_hosts = prior["known_network_destinations"]

    parsed_host = value
    if "://" in parsed_host:
        parsed_host = parsed_host.split("://", 1)[1]
    parsed_host = parsed_host.split("/", 1)[0].split(":", 1)[0].lower()

    if parsed_host in ("localhost", "127.0.0.1"):
        return False  # local proxy/dev override — not a hijack signal
    return not any(parsed_host == h or parsed_host.endswith("." + h) for h in known_hosts)


def is_agent_config_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(normalized.endswith(name) for name in AGENT_CONFIG_FILENAMES)


def is_mcp_config_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.endswith("/" + MCP_CONFIG_FILENAME) or normalized == MCP_CONFIG_FILENAME


# How long a pending config write is kept before being purged as stale, if
# nothing ever correlates against it. Deliberately above CONFIG_EXEC_WINDOW_SECONDS
# (2s) so it never purges an entry that check_malicious_config_execution
# would still consider in-window — this is a memory-growth safeguard, not
# part of the detection window itself.
PENDING_CONFIG_WRITE_TTL_SECONDS = 10
# Hard cap on pending entries, independent of TTL — keyed by agent_id so in
# practice this is bounded by concurrently-running distinct agents, but a
# cap is kept anyway as a defensive backstop against unbounded growth.
PENDING_CONFIG_WRITE_MAX_ENTRIES = 500

# TODO: ARCHITECTURAL DEBT — shared mutable state across independent
# RedLines() instances (file_watcher.py and process_watcher.py each hold
# their own instance, but both mutate this same module-level dict).
# Works correctly today with the TTL cleanup added below, but should be
# refactored to a proper shared store (e.g. a small SQLite table or a
# single shared RedLines() instance) before Layer 3 work begins, to avoid
# this becoming a real race condition under higher event volume.
_pending_config_writes: dict[int, dict] = {}


def _purge_stale_pending_config_writes() -> None:
    """TTL + size-cap cleanup for _pending_config_writes. Called on every
    record_config_write/pop_pending_config_write so the dict never grows
    unbounded over a long-running session, without needing its own
    scheduler job. Not async and does no I/O — safe to call from either
    watcher's sync or async context."""
    now = time.time()
    stale_keys = [
        agent_id for agent_id, entry in _pending_config_writes.items()
        if now - entry["ts"] > PENDING_CONFIG_WRITE_TTL_SECONDS
    ]
    for agent_id in stale_keys:
        _pending_config_writes.pop(agent_id, None)

    if len(_pending_config_writes) > PENDING_CONFIG_WRITE_MAX_ENTRIES:
        oldest_first = sorted(_pending_config_writes.items(), key=lambda kv: kv[1]["ts"])
        overflow = len(_pending_config_writes) - PENDING_CONFIG_WRITE_MAX_ENTRIES
        for agent_id, _ in oldest_first[:overflow]:
            _pending_config_writes.pop(agent_id, None)


# agent_id -> {"path": str, "ts": float} — most recent unresolved .mcp.json
# write, tracked separately from _pending_config_writes above since RL8's
# trigger is an MCP connection event, not a spawn/file-write, and its
# correlation window/session threshold are conceptually distinct even
# though they currently share the same values. Same TTL + module-level
# sharing tradeoffs as _pending_config_writes apply here (see the
# ARCHITECTURAL DEBT note above) — file_watcher.py records, mcp_watcher.py
# consumes.
_pending_mcp_config_writes: dict[int, dict] = {}


def _purge_stale_pending_mcp_writes() -> None:
    """Same TTL + size-cap cleanup as _purge_stale_pending_config_writes,
    applied to _pending_mcp_config_writes."""
    now = time.time()
    stale_keys = [
        agent_id for agent_id, entry in _pending_mcp_config_writes.items()
        if now - entry["ts"] > PENDING_CONFIG_WRITE_TTL_SECONDS
    ]
    for agent_id in stale_keys:
        _pending_mcp_config_writes.pop(agent_id, None)

    if len(_pending_mcp_config_writes) > PENDING_CONFIG_WRITE_MAX_ENTRIES:
        oldest_first = sorted(_pending_mcp_config_writes.items(), key=lambda kv: kv[1]["ts"])
        overflow = len(_pending_mcp_config_writes) - PENDING_CONFIG_WRITE_MAX_ENTRIES
        for agent_id, _ in oldest_first[:overflow]:
            _pending_mcp_config_writes.pop(agent_id, None)


class RedLines:
    """Fires the six Red Line rules and batches repeats within a 60s
    window per (agent_id, rule) so a noisy agent can't flood alerts."""

    def __init__(self):
        self.alerter = Alerter()
        # (agent_id, rule_key, target) -> {"last_fired": float, "batched": int}
        self._state: dict[tuple, dict] = {}

    async def _fire(
        self, agent_id: int, rule_key: str, severity: str, title: str, description: str, extra_detail: dict, target: str,
        rule_type: str = "red_line",
    ) -> None:
        """rule_type defaults to "red_line" — the non-disableable floor
        every existing call site relies on (api/alerts.py's resolve_alert
        gates purely on rule_type == "red_line"). RL3's normal-checkpoint
        tier is the one exception: it passes rule_type="checkpoint_activity"
        so it's dismissible like an ordinary alert, while still sharing
        this method's batching/dedup window logic — see
        check_claude_cache_write below."""
        now = time.time()
        window = RED_LINE_WINDOWS.get(rule_key, RED_LINE_WINDOW_SECONDS)
        state_key = (agent_id, rule_key, target)
        state = self._state.get(state_key)

        if state is not None and now - state["last_fired"] < window:
            state["batched"] += 1
            return

        if state is not None and state["batched"] > 0:
            description = f"{description} ({state['batched']} more {rule_key.replace('_', ' ')} events in the last {window // 60} min)"

        self._state[state_key] = {"last_fired": now, "batched": 0}

        await self.alerter.fire_alert(
            agent_id,
            severity,
            title=title,
            description=description,
            reason=f"red_line_{rule_key}" if rule_type == "red_line" else rule_key,
            extra_detail=extra_detail,
            rule_type=rule_type,
            target=target,
        )

    async def check_ssh_access(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_ssh_path(path):
            return
        await self._fire(
            agent_id, "ssh_access", "high",
            title=f"RED LINE: SSH directory accessed by {agent_name}",
            description=f"{agent_name} accessed your SSH directory. This is unusual and worth reviewing.",
            extra_detail={"path": path},
            target=path,
        )

    async def check_env_outside_workspace(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_env_outside_workspace(path):
            return
        await self._fire(
            agent_id, "env_outside_workspace", "high",
            title=f"RED LINE: environment file read outside workspace by {agent_name}",
            description=f"{agent_name} read an environment file outside your active project.",
            extra_detail={"path": path},
            target=path,
        )

    async def check_claude_cache_write(self, agent_id: int, agent_name: str, path: str, db) -> None:
        """RL3: hidden cache directory write. Two tiers, distinguishing
        normal /rewind checkpoint activity from genuinely anomalous writes:

          - Write correlates with an active/recently-active session for
            this agent (see has_active_or_recent_session): normal
            checkpoint activity. Fires severity="low",
            rule_type="checkpoint_activity" — informational, logged for
            audit, but dismissible like any regular alert (NOT gated by
            the red_line non-disableable check in api/alerts.py, since
            that gate keys on rule_type == "red_line" specifically).
          - No active/recent session at all: genuinely anomalous — a cache
            write with no corresponding Claude Code session in progress.
            Fires severity="high", rule_type="red_line" exactly as RL3
            did before this split — non-disableable, Accept-Risk only.
        """
        if not is_claude_cache_write(path):
            return
        # Dedup on the containing directory, not the individual snapshot
        # filename — Claude Code's file-history mechanism writes many
        # distinct per-turn snapshot files in a single burst under one
        # session directory, which is one logical event, not N.
        directory = str(Path(path.replace("\\", "/")).parent)

        if await has_active_or_recent_session(agent_id, db):
            await self._fire(
                agent_id, "checkpoint_activity", "low",
                title=f"{agent_name} checkpoint write (normal /rewind activity)",
                description=f"{agent_name} wrote to its hidden cache directory during an active session — "
                             "consistent with normal /rewind checkpoint behavior.",
                extra_detail={"path": path},
                target=directory,
                rule_type="checkpoint_activity",
            )
            return

        await self._fire(
            agent_id, "claude_cache_write", "high",
            title=f"RED LINE: {agent_name} wrote to hidden cache directory with no active session — unusual pattern",
            description=f"{agent_name} wrote to Claude's hidden cache directory with no active or recently-active "
                         "session in progress. This may include credential file copies and does not match normal "
                         "/rewind checkpoint behavior.",
            extra_detail={"path": path},
            target=directory,
        )

    async def check_unknown_destination(self, agent_id: int, agent_name: str, destination: str) -> None:
        if not is_unknown_destination(destination):
            return
        await self._fire(
            agent_id, "unknown_destination", "low",
            title=f"RED LINE: unrecognised network destination for {agent_name}",
            description=f"{agent_name} connected to an unrecognised destination: {destination}",
            extra_detail={"destination": destination},
            target=destination,
        )

    async def check_dangerous_command(self, agent_id: int, agent_name: str, cmdline: str, exe_basename: str = "") -> None:
        matched = is_dangerous_command(cmdline, exe_basename)
        if matched is None:
            return
        await self._fire(
            agent_id, "dangerous_command", "medium",
            title=f"RED LINE: sensitive command spawned by {agent_name}",
            description=f"{agent_name} spawned a potentially sensitive command: {cmdline}",
            extra_detail={"command": cmdline, "matched_pattern": matched},
            target=exe_basename or cmdline,
        )

    async def check_cross_project_read(self, agent_id: int, agent_name: str, path: str) -> None:
        if not is_cross_project_read(path):
            return
        await self._fire(
            agent_id, "cross_project_read", "medium",
            title=f"RED LINE: cross-project file read by {agent_name}",
            description=f"{agent_name} read files from a different project directory than the active workspace.",
            extra_detail={"path": path},
            target=path,
        )

    # FIXED: previously used get_agent_for_pid's "first match" logic which could
    # attribute RL7 to the wrong process when multiple instances of the same
    # agent binary are running. Now checks env vars per-PID independently.
    async def check_env_var_redirect(self, agent_id: int, agent_name: str, session_id: str, env_vars: dict, pid: int | None = None) -> None:
        """RL7: agent-config env var (ANTHROPIC_BASE_URL, OPENAI_BASE_URL,
        ...) redirected away from the agent's known official host.
        CVE-2026-21852 pattern. env_vars: {VAR_NAME: value}, already
        filtered to the relevant var names by the caller. Caller must pass
        the exact PID whose environment produced env_vars — see
        watchers/process_watcher.py::_scan_all_agent_processes_for_env_redirect,
        which independently inspects every currently-running process
        matching a known agent binary name, rather than relying on a single
        "first match" PID resolved by attributor.get_agent_for_pid. This
        ensures the alert is attributed to the specific process instance
        that actually had the redirect set, not a generically-resolved one,
        when multiple instances of the same agent binary are running
        concurrently (e.g. several claude.exe processes at once)."""
        for var_name, value in env_vars.items():
            if not is_env_var_redirect(agent_name, var_name, value):
                continue
            await self._fire(
                agent_id, "env_redirect", "critical",
                title=f"RED LINE: {agent_name} environment variable {var_name} redirected to unknown host — "
                      f"possible traffic hijack (CVE-2026-21852 pattern)",
                description=f"{agent_name}'s {var_name} was set to '{value}', which does not match its known "
                             "official API host. Traffic and credentials may be routed to an attacker-controlled endpoint.",
                extra_detail={"session_id": session_id, "var_name": var_name, "value": value, "pid": pid},
                target=f"{var_name}={value}",
            )

    def record_config_write(self, agent_id: int, config_path: str) -> None:
        """Marks config_path as a pending RL7b trigger candidate for
        agent_id. Shared at module level (see _pending_config_writes above)
        so both file_watcher.py (file-triggered correlation) and
        process_watcher.py (spawn-triggered correlation) see the same write,
        regardless of which watcher's RedLines() instance calls this."""
        if not is_agent_config_path(config_path):
            return
        _purge_stale_pending_config_writes()
        _pending_config_writes[agent_id] = {"path": config_path, "ts": time.time()}

    def pop_pending_config_write(self, agent_id: int) -> dict | None:
        """Returns and clears the pending config write for agent_id if one
        exists and is still within CONFIG_EXEC_WINDOW_SECONDS, else None."""
        _purge_stale_pending_config_writes()
        pending = _pending_config_writes.get(agent_id)
        if pending is None:
            return None
        if time.time() - pending["ts"] > CONFIG_EXEC_WINDOW_SECONDS:
            _pending_config_writes.pop(agent_id, None)
            return None
        return pending

    async def check_malicious_config_execution(
        self, agent_id: int, agent_name: str, config_path: str, config_write_ts: float,
        triggered_event_path: str, triggered_event_ts: float, prior_approved_sessions: int,
    ) -> None:
        """RL7b: a project config write (.claude/settings.json, .cursor/config,
        .vscode/settings.json) immediately followed (<= CONFIG_EXEC_WINDOW_SECONDS)
        by a process spawn or file write outside the config file itself, during
        an agent's early/first-use window (< CONFIG_EXEC_SESSION_THRESHOLD prior
        approved sessions). CVE-2025-59536 pattern: malicious config triggering
        execution before a user-facing trust dialog would normally appear.

        Caller is responsible for the actual event correlation (this method
        only evaluates one already-matched pair) — see record_config_write /
        pop_pending_config_write above for how file_watcher.py and
        process_watcher.py locate the pair."""
        if not is_agent_config_path(config_path):
            return
        if triggered_event_path == config_path:
            return
        if prior_approved_sessions >= CONFIG_EXEC_SESSION_THRESHOLD:
            return
        if (triggered_event_ts - config_write_ts) > CONFIG_EXEC_WINDOW_SECONDS:
            return

        await self._fire(
            agent_id, "config_exec", "critical",
            title=f"RED LINE: {agent_name} project config triggered immediate execution — "
                  f"possible pre-trust-dialog RCE (CVE-2025-59536 pattern)",
            description=f"{agent_name}'s config file {config_path} was written, then {triggered_event_path} "
                         f"was touched {round(triggered_event_ts - config_write_ts, 2)}s later — before this agent has "
                         f"built up trust ({prior_approved_sessions} prior approved sessions). This matches the "
                         "exploitation pattern of a malicious project config executing before any user approval.",
            extra_detail={
                "config_path": config_path,
                "triggered_event_path": triggered_event_path,
                "delay_seconds": round(triggered_event_ts - config_write_ts, 2),
                "prior_approved_sessions": prior_approved_sessions,
            },
            target=config_path,
        )

    def record_mcp_config_write(self, agent_id: int, config_path: str) -> None:
        """Marks a .mcp.json write as a pending RL8 trigger candidate for
        agent_id. Mirrors record_config_write's shared-module-level-state
        pattern (see _pending_mcp_config_writes above) — file_watcher.py
        records here, mcp_watcher.py consumes via pop_pending_mcp_config_write."""
        if not is_mcp_config_path(config_path):
            return
        _purge_stale_pending_mcp_writes()
        _pending_mcp_config_writes[agent_id] = {"path": config_path, "ts": time.time()}

    def pop_pending_mcp_config_write(self, agent_id: int) -> dict | None:
        """Returns and clears the pending .mcp.json write for agent_id if
        one exists and is still within MCP_AUTOAPPROVAL_WINDOW_SECONDS,
        else None."""
        _purge_stale_pending_mcp_writes()
        pending = _pending_mcp_config_writes.get(agent_id)
        if pending is None:
            return None
        if time.time() - pending["ts"] > MCP_AUTOAPPROVAL_WINDOW_SECONDS:
            _pending_mcp_config_writes.pop(agent_id, None)
            return None
        return pending

    async def check_mcp_auto_approval(
        self, agent_id: int, agent_name: str, mcp_config_path: str, config_write_ts: float,
        mcp_endpoint: str, mcp_connect_ts: float, is_approved_server: bool, prior_sessions_for_project: int,
    ) -> bool:
        """RL8: Detect MCP server auto-approval from untrusted project
        config, matching the MCP attack surface disclosed in CVE-2026-21852
        (Check Point Research, Jan 2026) — extends RL7's env-var-redirect
        coverage of the same CVE to project-scoped .mcp.json auto-approval.

        Fires only when BOTH:
          - mcp_endpoint is NOT in the approved_mcp_servers policy list, AND
          - this is one of the first MCP_AUTOAPPROVAL_SESSION_THRESHOLD
            sessions for this project directory (the CVE's actual
            exploitation window — an attacker relies on the victim opening
            an unfamiliar/new project, not a long-trusted one).

        Caller is responsible for the actual event correlation (a .mcp.json
        write followed by an MCP connection within
        MCP_AUTOAPPROVAL_WINDOW_SECONDS) and for resolving is_approved_server
        against policy's approved_mcp_servers — see record_mcp_config_write /
        pop_pending_mcp_config_write above for how file_watcher.py and
        mcp_watcher.py locate the pair. If either condition is false, the
        caller falls back to mcp_watcher.py's existing generic
        "Unapproved MCP server connection" alert (reason=unapproved_mcp,
        severity=high) instead — RL8 is the early-session, non-disableable
        escalation of that same signal, not a replacement for it.

        Returns True if RL8's conditions were met (regardless of whether the
        alert was actually inserted vs deduped by _fire's batching window) —
        callers use this to decide whether to suppress the generic fallback
        alert, not whether a new alert row was created."""
        if not is_mcp_config_path(mcp_config_path):
            return False
        if is_approved_server:
            return False
        if prior_sessions_for_project >= MCP_AUTOAPPROVAL_SESSION_THRESHOLD:
            return False
        if (mcp_connect_ts - config_write_ts) > MCP_AUTOAPPROVAL_WINDOW_SECONDS:
            return False

        server_name = mcp_endpoint.split(":", 1)[1] if ":" in mcp_endpoint else mcp_endpoint

        await self._fire(
            agent_id, "mcp_autoapproval", "critical",
            title=f"RED LINE: {agent_name} auto-approved an unrecognized MCP server ({mcp_endpoint}) "
                  f"from a new project directory — possible CVE-2026-21852 pattern",
            description=f"{agent_name}'s project config {mcp_config_path} was written, then it connected to "
                         f"MCP server '{mcp_endpoint}' {round(mcp_connect_ts - config_write_ts, 2)}s later — "
                         f"an unapproved server, in one of this project's first {MCP_AUTOAPPROVAL_SESSION_THRESHOLD} "
                         f"sessions ({prior_sessions_for_project} prior). This matches the MCP auto-approval attack "
                         "surface disclosed for CVE-2026-21852 by Check Point Research: a malicious repository's "
                         ".mcp.json connecting to an attacker-controlled MCP server before the user has reviewed it.",
            extra_detail={
                "mcp_config_path": mcp_config_path,
                "mcp_endpoint": mcp_endpoint,
                "server_name": server_name,
                "delay_seconds": round(mcp_connect_ts - config_write_ts, 2),
                "prior_sessions_for_project": prior_sessions_for_project,
            },
            target=mcp_endpoint,
        )
        return True
