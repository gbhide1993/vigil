"""Behavioural fallback for core.attributor: scores a process's recent
OS-level activity for AI-agent-like signatures, used only when
Attributor._walk_parent_chain can't match the process to a known agent by
name. Detects agents by HOW they behave (event timing, spread, targets),
never by what they call themselves.

Runs off a short-lived, read-only, synchronous sqlite3 connection rather
than the app's async aiosqlite handle, so it can be called from
Attributor.get_agent_for_pid -- including from watcher threads already
running in the executor pool, where there is no event loop to await
against. The DB runs in WAL mode (see db.database.init_db), which allows
this kind of concurrent read against the live writer without blocking
either side.
"""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("vlaw")

AGENT_LIKE_THRESHOLD = 0.6

FAST_INTERVAL_SECONDS = 0.1
FAST_INTERVAL_MIN_EVENTS = 5
DIR_SPAN_WINDOW_SECONDS = 3
DIR_SPAN_MIN_DIRS = 3
CHILD_SPAWN_WINDOW_SECONDS = 5
CHILD_SPAWN_MIN_COUNT = 3
IDLE_GAP_SECONDS = 3
IDLE_GAP_WINDOW_SECONDS = 10
IDLE_GAP_MIN_EVENTS = 5

# events.created_at is SQLite's default CURRENT_TIMESTAMP, which only has
# second resolution -- the sub-second signals below are only as precise
# as that; see get_recent_events_for_pid's docstring.
_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def _parse_timestamp(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.strptime(str(value)[:19], _TIMESTAMP_FORMAT).timestamp()
    except ValueError:
        return None


def _directory_of(path: str) -> str:
    normalized = path.replace("\\", "/")
    return normalized.rsplit("/", 1)[0] if "/" in normalized else ""


class BehaviourDetector:
    def get_recent_events_for_pid(self, pid: int, db: sqlite3.Connection, window_seconds: int = 10) -> list[dict]:
        """Events from the last `window_seconds` that bear on whether `pid`
        itself is agent-like: rows directly attributed to it (events.pid)
        plus, since a proc_spawn row's own pid is the spawned *child's* (see
        process_watcher.py), proc_spawn rows whose detail.parent_pid == pid
        -- that's what lets a spawning/orchestrating pid's own score pick up
        "I spawned N children in a burst" (see _has_child_spawn_cluster).

        `db` is expected to be a short-lived, read-only sqlite3.Connection
        with row_factory = sqlite3.Row (see Attributor._score_behaviour),
        not the app's async aiosqlite handle -- this method is synchronous
        so it can be called from Attributor.get_agent_for_pid as-is.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).strftime(_TIMESTAMP_FORMAT)
        try:
            cur = db.execute(
                """
                SELECT created_at, event_type, path, detail
                FROM events
                WHERE created_at >= ?
                  AND (
                        pid = ?
                        OR (event_type = 'proc_spawn' AND json_extract(detail, '$.parent_pid') = ?)
                      )
                ORDER BY created_at ASC
                """,
                (cutoff, pid, pid),
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            logger.exception("behaviour_detector: recent-events query failed for pid=%s", pid)
            return []

        return [
            {
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "path": row["path"],
                "detail": row["detail"],
            }
            for row in rows
        ]

    def score_process(self, pid: int, recent_events: list[dict]) -> float:
        """Additive confidence (0.0-1.0, capped) that `pid` is being driven
        by an AI agent rather than a human, based on recent_events (as
        returned by get_recent_events_for_pid). Never raises -- any bad or
        unexpected data just scores 0.0 rather than breaking attribution
        for the pid (see Attributor._score_behaviour, the only caller)."""
        try:
            return self._score(recent_events)
        except Exception:
            logger.exception("behaviour_detector: scoring failed for pid=%s", pid)
            return 0.0

    def _score(self, recent_events: list[dict]) -> float:
        if not recent_events:
            return 0.0

        events = []
        for event in recent_events:
            ts = _parse_timestamp(event.get("created_at"))
            if ts is None:
                continue
            events.append({**event, "_ts": ts})
        events.sort(key=lambda e: e["_ts"])

        if not events:
            return 0.0

        score = 0.0
        if self._has_fast_interval_burst(events):
            score += 0.4
        if self._spans_multiple_directories(events):
            score += 0.3
        if self._hits_known_agent_destination(events):
            score += 0.3
        if self._has_child_spawn_cluster(events):
            score += 0.2
        if self._has_no_idle_gaps(events):
            score += 0.2

        return min(score, 1.0)

    def _has_fast_interval_burst(self, events: list[dict]) -> bool:
        """+0.4: average inter-event interval < 100ms across some run of
        5+ consecutive events."""
        if len(events) < FAST_INTERVAL_MIN_EVENTS:
            return False
        for i in range(len(events) - FAST_INTERVAL_MIN_EVENTS + 1):
            window = events[i:i + FAST_INTERVAL_MIN_EVENTS]
            intervals = [window[j + 1]["_ts"] - window[j]["_ts"] for j in range(len(window) - 1)]
            if intervals and (sum(intervals) / len(intervals)) < FAST_INTERVAL_SECONDS:
                return True
        return False

    def _spans_multiple_directories(self, events: list[dict]) -> bool:
        """+0.3: file reads span 3+ different directories in under 3s."""
        file_events = [e for e in events if e["event_type"] in ("file_read", "file_write") and e.get("path")]
        if len(file_events) < DIR_SPAN_MIN_DIRS:
            return False
        for i, start in enumerate(file_events):
            window_end = start["_ts"] + DIR_SPAN_WINDOW_SECONDS
            window = [e for e in file_events[i:] if e["_ts"] <= window_end]
            dirs = {_directory_of(e["path"]) for e in window}
            if len(dirs) >= DIR_SPAN_MIN_DIRS:
                return True
        return False

    def _hits_known_agent_destination(self, events: list[dict]) -> bool:
        """+0.3: a net_connect event hit a known AI-API destination."""
        from core.attributor import KNOWN_DESTINATIONS  # deferred: core.attributor
        # imports BehaviourDetector at module scope, so importing it back
        # at module scope here would be a circular import.

        known_hosts = set(KNOWN_DESTINATIONS.keys())
        for event in events:
            if event["event_type"] != "net_connect":
                continue
            host = event.get("path") or ""
            if host in known_hosts or any(host.endswith(h) for h in known_hosts):
                return True
        return False

    def _has_child_spawn_cluster(self, events: list[dict]) -> bool:
        """+0.2: 3+ child processes spawned within 5 seconds."""
        spawns = [e for e in events if e["event_type"] == "proc_spawn"]
        if len(spawns) < CHILD_SPAWN_MIN_COUNT:
            return False
        for i, start in enumerate(spawns):
            window_end = start["_ts"] + CHILD_SPAWN_WINDOW_SECONDS
            count = sum(1 for e in spawns[i:] if e["_ts"] <= window_end)
            if count >= CHILD_SPAWN_MIN_COUNT:
                return True
        return False

    def _has_no_idle_gaps(self, events: list[dict]) -> bool:
        """+0.2: no gap > 3s between consecutive events, across a
        10-second window that has 5+ events in it."""
        window = [e for e in events if e["_ts"] >= events[-1]["_ts"] - IDLE_GAP_WINDOW_SECONDS]
        if len(window) < IDLE_GAP_MIN_EVENTS:
            return False
        gaps = [window[i + 1]["_ts"] - window[i]["_ts"] for i in range(len(window) - 1)]
        return all(gap <= IDLE_GAP_SECONDS for gap in gaps)
