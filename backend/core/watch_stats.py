"""Cheap in-memory counters for file changes Vigil deliberately did not
record: changes in generated or dependency folders (core/ignore_rules.py)
and changes dropped because too many arrived at once. Counted since the
backend started; shown in the report so a quiet number is never mistaken
for "nothing happened". Increments come from watcher threads, hence the lock.
"""

import threading
import time
from datetime import datetime, timezone

_lock = threading.Lock()
_ignored: dict[str, int] = {}
_dropped: dict[str, int] = {"overload": 0, "buffer_full": 0}
_out_of_scope = 0
_unresolved = 0
_since = time.time()


def count_ignored(folder: str) -> None:
    with _lock:
        _ignored[folder] = _ignored.get(folder, 0) + 1


def ignored_by_folder() -> dict[str, int]:
    with _lock:
        return dict(_ignored)


def ignored_total() -> int:
    with _lock:
        return sum(_ignored.values())


def add_dropped(kind: str) -> None:
    with _lock:
        _dropped[kind] = _dropped.get(kind, 0) + 1


def dropped_total() -> int:
    with _lock:
        return sum(_dropped.values())


def dropped_by_kind() -> dict[str, int]:
    """Changes dropped because too many arrived at once, by where they were dropped: "overload" (the file watcher's
    in-flight limit) and "buffer_full" (the write buffer)."""
    with _lock:
        return dict(_dropped)


def add_out_of_scope() -> None:
    """An ETW file change seen but not recorded because it is outside the watched folders, the credential paths and
    the agents' state folders (core/scope_filter.py). Counted only; this is not a drop."""
    global _out_of_scope
    with _lock:
        _out_of_scope += 1


def add_unresolved() -> None:
    """An ETW file change seen but not recorded because the trace gave no file name for it and none could be
    taken from an earlier open of the same file. Counted only."""
    global _unresolved
    with _lock:
        _unresolved += 1


def unresolved_total() -> int:
    with _lock:
        return _unresolved


def out_of_scope_total() -> int:
    with _lock:
        return _out_of_scope


def summary() -> dict:
    """What /health reports: everything Vigil saw and deliberately or unavoidably did not record, since start."""
    with _lock:
        return {
            "since": since_iso(),
            "dropped_total": sum(_dropped.values()),
            "dropped_by_kind": dict(_dropped),
            "outside_scope_not_recorded": _out_of_scope,
            "no_file_name_not_recorded": _unresolved,
            "ignored_generated_changes": sum(_ignored.values()),
        }


def since_iso() -> str:
    return datetime.fromtimestamp(_since, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def reset() -> None:
    """For tests."""
    global _since, _out_of_scope, _unresolved
    with _lock:
        _out_of_scope = 0
        _unresolved = 0
        _ignored.clear()
        for k in _dropped:
            _dropped[k] = 0
        _since = time.time()
