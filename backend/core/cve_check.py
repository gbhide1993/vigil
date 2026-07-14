"""
CVE version thresholds below are independently verified against primary
sources (NVD, GitHub Security Advisory, Check Point Research) as of July 2026.

One field remains unconfirmed: CVE-2026-21852's CVSS 3.1 score (see inline
comment) — do not cite this specific number publicly until verified directly.

cursor and copilot entries are empty because no CVE research has been done
for those agents yet, not because none exist. Do not claim "no known CVEs"
publicly for cursor/copilot until this list is actually researched.
"""

import json
import re
import shutil
import subprocess

KNOWN_CVES = {
    "claude_code": [
        {
            "cve_id": "CVE-2025-59536",
            "affected_versions_below": "1.0.111",  # CONFIRMED via NVD + GHSA-4fgq-fpq9-mr3g + Check Point Research
            "description": "Code injection via startup trust dialog bypass — project code could execute before user accepted the trust prompt",
            "severity": "critical",  # CVSS 3.1: 8.8, CVSS 4.0: 8.7
            "cwe": "CWE-94",
            "source": "https://github.com/anthropics/claude-code/security/advisories/GHSA-4fgq-fpq9-mr3g",
            "disclosed": "2025-10-03",
        },
        {
            "cve_id": "CVE-2026-21852",
            "affected_versions_below": "2.0.65",  # CONFIRMED via MintMCP + cross-referenced security guide
            "description": "ANTHROPIC_BASE_URL override via malicious project config redirects API traffic and leaks API keys before trust confirmation. Related attack surfaces per Check Point Research: Hooks and MCP server auto-approval, not just environment variables.",
            "severity": "critical",  # CVSS 4.0: 5.3 confirmed. CVSS 3.1 score of 7.5 is UNCONFIRMED against primary NVD source — do not cite publicly until directly verified at nvd.nist.gov
            "cwe": None,  # VERIFY: not confirmed in sources reviewed
            "source": "https://www.cve.org/CVERecord?id=CVE-2026-21852",
            "disclosed": "2026-01-21",
        },
    ],
    "cursor": [],  # No known CVEs tracked yet — not confirmed absent, just not yet researched
    "copilot": [],  # No known CVEs tracked yet — not confirmed absent, just not yet researched
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
