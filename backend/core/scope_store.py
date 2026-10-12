"""The single source of truth for which project folders Vigil watches
(`scope_directories`), plus the rules for adding one.

DECISION (single source of truth): the DATABASE copy is authoritative. The
policy file (policy/vlaw-policy.json) is only a seed: init_db copies it into
the `policy` table the first time a key is missing (it never overwrites an
existing row), and this module falls back to the file only when the database
has no `scope_directories` row at all. An existing database value is always
preserved, including an empty list: the user may have removed every folder.
Before this change the file watcher read the file at startup while the
out-of-scope alert logic read the database, so the two could disagree (on
the developer machine the file said [] and the database held
["C:/Users/gbhid/vlaw"]). Every reader now goes through get_scope_directories:
the file watcher at startup, the live add/remove API, the out-of-scope alert
logic and the report. Editing the policy file after the first run therefore
no longer changes what is watched; use Settings (or POST /api/scope).

Folders are stored as strings (the format alert logic already reads), in
forward-slash form. When each folder was added and by whom is kept in a
second policy row, `scope_directories_meta`; entries without metadata
(added before this existed) report the scope row's own updated_at.
"""

import json
import os
import sys
from pathlib import Path

from core.own_paths import own_roots

SCOPE_KEY = "scope_directories"
META_KEY = "scope_directories_meta"
MAX_FOLDERS = 20


class ScopeError(Exception):
    """A refusal with a stable machine-readable code and a plain message."""

    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


# ------------------------------------------------------------------ storage

def _load_seed_from_file() -> list[str]:
    from config.policy import load_policy

    try:
        value = load_policy().get(SCOPE_KEY, [])
    except (OSError, ValueError):
        return []
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


async def _row(db, key: str):
    cur = await db.execute("SELECT policy_value, updated_at FROM policy WHERE policy_key = ?", (key,))
    return await cur.fetchone()


async def get_scope_directories(db) -> list[str]:
    """The watched project folders. The database row wins (even when it is
    an empty list); the policy file is consulted only if there is no row."""
    row = await _row(db, SCOPE_KEY)
    if row is not None:
        try:
            value = json.loads(row["policy_value"])
        except ValueError:
            value = []
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []
    return _load_seed_from_file()


async def get_scope_entries(db) -> list[dict]:
    """[{path, added_at, source}] for the API and the reports."""
    paths = await get_scope_directories(db)
    row = await _row(db, SCOPE_KEY)
    fallback_added = row["updated_at"] if row is not None else None
    meta_row = await _row(db, META_KEY)
    try:
        meta = json.loads(meta_row["policy_value"]) if meta_row is not None else {}
    except ValueError:
        meta = {}
    entries = []
    for path in paths:
        info = meta.get(path, {}) if isinstance(meta, dict) else {}
        entries.append({
            "path": path,
            "added_at": info.get("added_at") or fallback_added,
            "source": info.get("source") or "user",
        })
    return entries


async def _upsert(db, key: str, value) -> None:
    await db.execute(
        """
        INSERT INTO policy (policy_key, policy_value) VALUES (?, ?)
        ON CONFLICT(policy_key) DO UPDATE SET policy_value = excluded.policy_value,
                                              updated_at = CURRENT_TIMESTAMP
        """,
        (key, json.dumps(value)),
    )


async def save_scope(db, paths: list[str], meta: dict) -> None:
    """Persists the folder list and the per-folder metadata (database only;
    the policy file is a seed and is not written)."""
    await _upsert(db, SCOPE_KEY, paths)
    await _upsert(db, META_KEY, {p: meta[p] for p in paths if p in meta})
    await db.commit()


async def get_meta(db) -> dict:
    row = await _row(db, META_KEY)
    try:
        value = json.loads(row["policy_value"]) if row is not None else {}
    except ValueError:
        value = {}
    return value if isinstance(value, dict) else {}


# --------------------------------------------------------------- validation

def normalise(path: str) -> str:
    """Absolute, forward-slash form used for storage."""
    return Path(os.path.abspath(path)).as_posix()


def _key(path: str) -> str:
    """Comparison key: case-insensitive on Windows, no trailing slash."""
    return os.path.normcase(os.path.abspath(path)).replace("\\", "/").rstrip("/")


def _is_within(child: str, parent: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def _is_network_drive(path: str) -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive:
            return False
        return ctypes.windll.kernel32.GetDriveTypeW(drive + "\\") == 4   # DRIVE_REMOTE
    except Exception:
        return False


def _forbidden_system_roots() -> list[tuple[str, str]]:
    """(key, label) for system folders that are never watched project folders."""
    roots = []
    for env, label in (("SystemRoot", "the Windows folder"), ("windir", "the Windows folder"),
                       ("ProgramFiles", "Program Files"), ("ProgramFiles(x86)", "Program Files (x86)"),
                       ("ProgramW6432", "Program Files")):
        value = os.environ.get(env)
        if value:
            roots.append((_key(value), label))
    if sys.platform == "win32":
        for literal, label in (("C:/Windows", "the Windows folder"), ("C:/Program Files", "Program Files"),
                               ("C:/Program Files (x86)", "Program Files (x86)")):
            roots.append((_key(literal), label))
    return roots


def validate_new_folder(raw: object, existing: list[str], *, home: str | None = None) -> str:
    """Returns the normalised path to store, or raises ScopeError."""
    if not isinstance(raw, str) or not raw.strip():
        raise ScopeError(400, "empty_path", "Enter the full path of a folder.")
    raw = raw.strip().strip('"')

    if raw.startswith("\\\\") or raw.startswith("//"):
        raise ScopeError(400, "network_path", "Network (UNC) paths cannot be watched. Choose a folder on this computer.")
    if _is_network_drive(raw):
        raise ScopeError(400, "network_drive", "Folders on a network drive cannot be watched. Choose a folder on this computer.")
    if not os.path.exists(raw):
        raise ScopeError(400, "not_found", "That folder does not exist.")
    if not os.path.isdir(raw):
        raise ScopeError(400, "not_a_directory", "That path is a file, not a folder.")

    resolved = os.path.realpath(raw)
    key = _key(resolved)
    stored = normalise(resolved)

    if os.path.splitdrive(resolved)[1].strip("\\/") == "":
        raise ScopeError(400, "drive_root", "A whole drive cannot be watched. Choose a project folder.")

    home_path = home if home is not None else os.path.expanduser("~")
    if key == _key(home_path):
        raise ScopeError(400, "home_folder", "Your whole home folder cannot be watched. Choose a specific project folder inside it.")
    if _is_within(_key(home_path), key):
        raise ScopeError(400, "contains_home", "That folder contains your home folder. Choose a specific project folder.")

    for system_key, label in _forbidden_system_roots():
        if _is_within(key, system_key) or _is_within(system_key, key):
            raise ScopeError(400, "system_folder", f"{label} cannot be watched.")

    for own in own_roots():
        if _is_within(key, own) or _is_within(own, key):
            raise ScopeError(400, "vigil_folder", "Vigil's own install and data folders cannot be watched.")

    # Already watched by a fixed rule.
    for fixed in (_key(os.path.join(home_path, ".ssh")), _key(os.path.join(home_path, ".claude", "file-history"))):
        if _is_within(key, fixed) or _is_within(fixed, key):
            raise ScopeError(409, "already_watched_fixed", "That folder is already watched by a built-in rule (.ssh or Claude's checkpoint cache).")

    existing_keys = [(e, _key(e)) for e in existing]
    for original, existing_key in existing_keys:
        if key == existing_key:
            raise ScopeError(409, "duplicate", "That folder is already watched.")
        if _is_within(key, existing_key):
            raise ScopeError(409, "inside_watched", f"That folder is already covered by the watched folder {original}.")
    contained = [original for original, existing_key in existing_keys if _is_within(existing_key, key)]
    if contained:
        raise ScopeError(409, "contains_watched",
                         "That folder contains an already watched folder (" + ", ".join(contained) + "). Remove it first.")

    if len(existing) >= MAX_FOLDERS:
        raise ScopeError(409, "too_many", f"At most {MAX_FOLDERS} folders can be watched. Remove one first.")

    return stored


def find_entry(path: object, existing: list[str]) -> str | None:
    """The stored spelling of `path` if it is in `existing` (case-insensitive)."""
    if not isinstance(path, str) or not path.strip():
        return None
    wanted = _key(path.strip().strip('"'))
    for original in existing:
        if _key(original) == wanted:
            return original
    return None
