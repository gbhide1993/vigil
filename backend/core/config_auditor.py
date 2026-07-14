"""Audits the user's own native Claude Code config (permissions.allow /
permissions.deny in settings.json) against a recommended baseline, and
tells them exactly what's missing. Read-only — never writes to the
user's config.

Confirmed real paths and schema on a real dev machine (2026-07-14):
  - Global: ~/.claude/settings.json — e.g. {"effortLevel": "medium", "model": "sonnet"}.
    No "permissions" key present on this machine at all.
  - Project-level: <project>/.claude/settings.local.json — e.g.
    {"permissions": {"allow": ["Read(//c/Users/gbhid/**)", "Bash(mkdir -p ...)"]}}.
    permissions.allow is confirmed to be a flat list of "Tool(pattern)"
    strings. permissions.deny was NOT present anywhere on this machine, so
    its exact pattern syntax is inferred from the allow-list shape, not
    independently confirmed — matching below is deliberately
    substring-tolerant rather than assuming brittle exact equality.
  - <project>/.claude/settings.json (the non-local, shared variant) is also
    a real Claude Code config location per the allow-list schema above,
    even though only settings.local.json exists on this machine.
"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("vlaw")

# Starting baseline only — not exhaustive. Grow this list as real-world
# attack/misuse patterns are identified through actual Vigil alert data
# over time (e.g. new Red Line rules should usually get a matching entry
# here once they've proven out).
RECOMMENDED_DENY_PATTERNS = [
    {"pattern": "Write(.env)", "reason": "Prevents direct .env file modification", "severity": "critical"},
    {"pattern": "Edit(.env)", "reason": "Prevents .env file edits", "severity": "critical"},
    {"pattern": "Write(.ssh/*)", "reason": "Prevents SSH key modification", "severity": "critical"},
    {"pattern": "Read(.ssh/id_rsa)", "reason": "Prevents SSH private key access", "severity": "critical"},
    {"pattern": "Write(.aws/*)", "reason": "Prevents AWS credential modification", "severity": "high"},
    {"pattern": "Bash(cat > .env)", "reason": "Prevents shell-based .env overwrite", "severity": "high"},
    {"pattern": "Bash(sed -i:* .env)", "reason": "Prevents in-place .env modification via sed", "severity": "medium"},
    {"pattern": "Bash(curl:*)", "reason": "Flags unrestricted outbound curl usage", "severity": "medium"},
    {"pattern": "Bash(wget:*)", "reason": "Flags unrestricted outbound wget usage", "severity": "medium"},
]


def find_claude_config_paths(project_dir: str | None = None) -> list[str]:
    """Locates all Claude Code config files that actually exist on disk.
    Checks, in order: global (~/.claude/settings.json), project-level
    shared (<project>/.claude/settings.json), and project-level local
    (<project>/.claude/settings.local.json — confirmed real on this
    machine). Only returns paths that exist; never fabricates a path."""
    project_dir = project_dir or os.getcwd()

    candidates = [
        os.path.expanduser("~/.claude/settings.json"),
        os.path.join(project_dir, ".claude", "settings.json"),
        os.path.join(project_dir, ".claude", "settings.local.json"),
    ]
    return [p for p in candidates if os.path.isfile(p)]


def parse_claude_config(path: str) -> dict:
    """Parses a Claude Code settings.json file. Returns {} with a logged
    warning if the file doesn't exist or isn't valid JSON — never raises."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        logger.warning("config_auditor: file not found: %s", path)
        return {}
    except json.JSONDecodeError as e:
        logger.warning("config_auditor: malformed JSON in %s: %s", path, e)
        return {}
    except OSError as e:
        logger.warning("config_auditor: could not read %s: %s", path, e)
        return {}


def _extract_deny_list(config: dict) -> list[str]:
    """permissions.deny is a flat list of "Tool(pattern)" strings, mirroring
    the confirmed-real permissions.allow shape. Tolerates a missing
    permissions key (confirmed real on this machine's global config) or a
    missing deny key (confirmed real on this machine's project config)."""
    permissions = config.get("permissions")
    if not isinstance(permissions, dict):
        return []
    deny = permissions.get("deny")
    if not isinstance(deny, list):
        return []
    return [d for d in deny if isinstance(d, str)]


def _pattern_covered(recommended_pattern: str, deny_list: list[str]) -> bool:
    """Matches a recommended pattern against the user's actual deny list.
    Deliberately not exact-equality-only: the real deny syntax wasn't
    directly observable on this machine (no populated deny list existed
    to confirm against), so an exact match OR a substring match in either
    direction is treated as "covered" — e.g. a user's own broader
    "Write(.env*)" should count as covering our narrower "Write(.env)"
    recommendation, and vice versa for a narrower user rule under a
    broader recommendation."""
    for entry in deny_list:
        if entry == recommended_pattern:
            return True
        if recommended_pattern in entry or entry in recommended_pattern:
            return True
    return False


def audit_config(config: dict) -> dict:
    """Compares config's permissions.deny against RECOMMENDED_DENY_PATTERNS.
    Returns {"configured": [...], "missing": [...], "coverage_score": float}."""
    deny_list = _extract_deny_list(config)

    configured = []
    missing = []
    for rec in RECOMMENDED_DENY_PATTERNS:
        if _pattern_covered(rec["pattern"], deny_list):
            configured.append(rec)
        else:
            missing.append(rec)

    total = len(RECOMMENDED_DENY_PATTERNS)
    coverage_score = round(len(configured) / total * 100, 1) if total else 0.0

    return {
        "configured": configured,
        "missing": missing,
        "coverage_score": coverage_score,
    }


def audit_all_configs(project_dir: str | None = None) -> dict:
    """Runs the audit against every Claude Code config file found (global +
    project-level), merging their deny lists before scoring — a pattern
    denied in either file counts as configured, since Claude Code applies
    both. Returns audit_config()'s result plus which file(s) were read.
    If no config file exists at all, returns zero coverage with every
    recommended pattern listed as missing."""
    paths = find_claude_config_paths(project_dir)

    merged: dict = {"permissions": {"deny": []}}
    seen_deny: set[str] = set()
    for path in paths:
        config = parse_claude_config(path)
        for entry in _extract_deny_list(config):
            if entry not in seen_deny:
                seen_deny.add(entry)
                merged["permissions"]["deny"].append(entry)

    result = audit_config(merged)
    result["config_paths_read"] = paths
    result["config_found"] = bool(paths)
    return result
