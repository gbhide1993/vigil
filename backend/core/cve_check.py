"""
WARNING: CVE version thresholds in this file are UNVERIFIED PLACEHOLDERS.
Do not ship to production or make public claims about CVE detection until
every "affected_versions_below" value has been checked against Anthropic's
actual published security advisories.
"""

import json
import re
import shutil
import subprocess

# VERIFY: every affected_versions_below value below is a placeholder pending
# manual confirmation against Anthropic's actual published security
# advisories. Do NOT ship, and do NOT surface these to users, until each one
# has been checked against the real advisory — a wrong "patched version"
# number is worse than no data, since it can tell an actually-vulnerable
# user they're safe.
KNOWN_CVES = {
    "claude_code": [
        {
            "cve_id": "CVE-2025-59536",
            "affected_versions_below": "1.18.0",  # VERIFY: UNCONFIRMED — CHECK ANTHROPIC SECURITY ADVISORY BEFORE SHIPPING
            "description": "Malicious project config can trigger remote code execution before trust dialog",
            "severity": "critical",
        },
        {
            "cve_id": "CVE-2026-21852",
            "affected_versions_below": "1.19.0",  # VERIFY: UNCONFIRMED — CHECK ANTHROPIC SECURITY ADVISORY BEFORE SHIPPING
            "description": "ANTHROPIC_BASE_URL environment variable manipulation allows silent traffic redirection and credential exfiltration",
            "severity": "critical",
        },
    ],
    # No known CVEs tracked yet for these agents — placeholders so
    # check_agent_cves() has a defined (empty) result instead of falling
    # through to "unknown agent".
    "cursor": [],
    "copilot": [],
}

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _parse_version(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(version)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def _version_below(installed: str, threshold: str) -> bool | None:
    """Returns True/False, or None if either version string can't be
    parsed — callers must treat None as "can't determine", never as False."""
    installed_parsed = _parse_version(installed)
    threshold_parsed = _parse_version(threshold)
    if installed_parsed is None or threshold_parsed is None:
        return None
    return installed_parsed < threshold_parsed


def get_installed_agent_version(agent_name: str) -> str | None:
    """Attempt to determine the installed version of the agent binary.
    Returns None if the version cannot be determined — never guesses.

    claude_code: runs `claude --version` (the CLI's own self-report is the
    only reliable cross-platform source available without hardcoding
    install-path assumptions that differ between npm-global, Homebrew, and
    the standalone installer).
    """
    if agent_name != "claude_code":
        return None  # VERIFY: no version-detection strategy implemented yet for cursor/copilot

    exe = shutil.which("claude") or shutil.which("claude.cmd")
    if exe is None:
        return None

    try:
        result = subprocess.run(
            [exe, "--version"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    parsed = _parse_version(result.stdout.strip())
    if parsed is None:
        return None
    return ".".join(str(p) for p in parsed)


def check_agent_cves(agent_name: str) -> list[dict]:
    """Compares the installed version of agent_name against KNOWN_CVES.
    Returns a list of applicable CVE dicts (each with an added
    "installed_version" key), or [] if none apply or the version is
    unknown — an unknown version is treated as "cannot confirm", not as
    "vulnerable", since fabricating a match would be worse than silence."""
    candidates = KNOWN_CVES.get(agent_name, [])
    if not candidates:
        return []

    installed_version = get_installed_agent_version(agent_name)
    if installed_version is None:
        return []

    applicable = []
    for cve in candidates:
        is_affected = _version_below(installed_version, cve["affected_versions_below"])
        if is_affected:
            applicable.append({**cve, "installed_version": installed_version})

    return applicable
