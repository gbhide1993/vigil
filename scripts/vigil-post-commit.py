#!/usr/bin/env python3
# Vigil evidence hook — installed by Vigil v0.2.1-beta
# Remove this file or run: vigil uninstall-hook to disable
#
# Runs as .git/hooks/post-commit. Attaches recent AI-agent evidence
# (from Vigil's local API) to the commit as a git note. Must never
# block or slow down a commit: any failure exits 0 silently, and the
# API call is capped at 3 seconds.

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VIGIL_URL = "http://localhost:7422/git/commit-summary"
TIMEOUT_SECONDS = 3
LOG_PATH = Path.home() / ".vigil" / "commit-evidence.jsonl"


def _fetch_evidence() -> dict | None:
    try:
        import urllib.request

        req = urllib.request.Request(VIGIL_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _format_note(evidence: dict) -> str:
    lines = []
    lines.append("--- VIGIL EVIDENCE ---")
    lines.append(f"Vigil v{evidence.get('vigil_version', 'unknown')}")
    lines.append(f"Generated: {evidence.get('generated_at', '')}")
    lines.append("")

    sessions = evidence.get("sessions", [])
    lines.append(f"AI Sessions: {len(sessions)}")
    for s in sessions:
        agent = s.get("agent", "unknown")
        duration = s.get("duration_min", 0)
        file_count = len(s.get("files_touched", []))
        lines.append(f"  [{agent}] {duration}min - {file_count} files")
    lines.append("")

    signals = evidence.get("friction_signals", [])
    lines.append(f"Friction Signals: {len(signals)}")
    for sig in signals:
        confidence = sig.get("confidence", 0.0)
        lines.append(f"  [{confidence:.0%}] {sig.get('type', '')} - {sig.get('file', '')}")
    lines.append("")

    lines.append(f"Red Lines: {evidence.get('red_lines', 0)}")
    lines.append(f"Evidence Hash: {evidence.get('evidence_hash', '')}")
    lines.append("----------------------")
    return "\n".join(lines)


def main() -> int:
    evidence = _fetch_evidence()
    if evidence is None:
        return 0

    sessions = evidence.get("sessions", [])
    if not sessions:
        return 0

    try:
        commit_hash = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
    except Exception:
        return 0

    note = _format_note(evidence)

    try:
        subprocess.run(
            ["git", "notes", "--ref", "refs/notes/vigil-evidence", "add", "-f", "-m", note, commit_hash],
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
        )
    except Exception:
        return 0

    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "commit": commit_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence,
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

    print(f"  ✓ Vigil: evidence attached to commit {commit_hash[:8]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
