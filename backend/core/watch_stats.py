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


def since_iso() -> str:
    return datetime.fromtimestamp(_since, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def reset() -> None:
    """For tests."""
    global _since
    with _lock:
        _ignored.clear()
        for k in _dropped:
            _dropped[k] = 0
        _since = time.time()
