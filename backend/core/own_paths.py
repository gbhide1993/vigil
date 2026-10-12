"""Vigil's own folders: its install folder and its data folder (the V-LAW
directory under %LOCALAPPDATA%). Changes there are Vigil's own activity
(database, logs, updates), never an agent's, so they are never recorded as
file events regardless of how the watch list is configured, and they cannot
be added as a watched project folder.
"""

import os
import sys
from pathlib import Path

_cache: list[str] | None = None


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).replace("\\", "/").rstrip("/")


def own_roots() -> list[str]:
    """Normalised (lower-case on Windows, forward-slash) own folders."""
    global _cache
    if _cache is not None:
        return _cache

    roots: list[str] = []

    def add(p) -> None:
        if p:
            n = _norm(str(p))
            if n and n not in roots:
                roots.append(n)

    # The data folder this process actually uses, and the standard V-LAW folder.
    data_dir = os.environ.get("VLAW_DATA_DIR")
    if data_dir:
        add(data_dir)
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        add(Path(local_app_data) / "V-LAW")
    # The install folder: wherever the frozen backend lives (app\backend\...,
    # so the app root is its parent, which also holds the tray), and the
    # default install location.
    if getattr(sys, "frozen", False):
        add(Path(sys.executable).resolve().parent.parent)
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        add(Path(program_files) / "Vigil")

    _cache = roots
    return roots


def reset_cache() -> None:
    """For tests that change the environment the roots are derived from."""
    global _cache
    _cache = None


def is_own_path(path: str | None) -> bool:
    if not path:
        return False
    n = _norm(path)
    return any(n == root or n.startswith(root + "/") for root in own_roots())
