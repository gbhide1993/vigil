"""Loads the policy definition JSON file. The seeded copy lives in the
DB (policy table); this loader is used at startup before the DB is
necessarily populated, e.g. to get scope_directories for the file
watcher's initial observer.schedule() calls."""

import json
import os
from pathlib import Path

POLICY_FILE = Path(os.environ.get("VLAW_POLICY_FILE", "./policy/vlaw-policy.json"))


def load_policy() -> dict:
    if not POLICY_FILE.exists():
        return {}
    return json.loads(POLICY_FILE.read_text())
