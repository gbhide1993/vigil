"""Red line "mass_delete": many files deleted under one watched folder within a few seconds.

Fed at ingress, before the aggregator's buffer, so it counts every change the watcher saw. A summary row counts for the
changes it stands for (its file count), so an overflow cannot hide a deletion. Per watched root a sliding 10 s window is
kept; crossing the threshold fires one critical alert per root per 60 s.

Honest limits: the file watcher does not know which process deleted a file. The alert says which agents were running and,
if the process watcher saw a delete tool start under an agent in the window, names it as a possible link (medium
confidence, not verified). Otherwise it says no process was observed. Folders are not counted, only files; a folder event
is recognised by the watcher's own is_directory flag, or because files in it were deleted a moment earlier.
"""

import asyncio
import logging
import os
import re
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone

logger = logging.getLogger("vlaw")

WINDOW_SECONDS = 10
COOLDOWN_SECONDS = 60
# After the threshold is crossed, wait this long before writing the alert so a delete tool that started a moment earlier
# (seen by the 1 s process snapshot) can be named in it.
GRACE_SECONDS = 2.0
THRESHOLD_FLOOR = 150
# Largest count of file deletions in one 10 s window under one watched folder over this machine's history (read from a
# copy of the live database on 2026-11-23); the default threshold is three times it.
BASELINE_MAX = 301
ROOTS_REFRESH_SECONDS = 10

# A delete tool in a command line: rm, rmdir, rd, del, erase, Remove-Item (with or without .exe), as a word.
DELETE_TOOL = re.compile(r"(?:^|[\s\"'/\\;&|(])(rm|rmdir|rd|del|erase|remove-item)(?:\.exe)?(?=$|[\s\"';&|)])", re.IGNORECASE)


def threshold() -> int:
    raw = os.environ.get("VLAW_MASS_DELETE_THRESHOLD", "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            logger.warning("VLAW_MASS_DELETE_THRESHOLD=%r is not a number; using the default", raw)
    return max(THRESHOLD_FLOOR, 3 * BASELINE_MAX)


def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").rstrip("/").lower()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class _Root:
    def __init__(self, display: str):
        self.display = display
        self.window: deque = deque()      # (ts, count, top-level folder)
        self.total = 0
        self.folder_events: deque = deque()   # ts of each folder event
        self.dirs_seen: dict[str, float] = {}  # directory -> ts of the last file deleted in it
        self.last_fired = 0.0
        self.pending = False
        self.agent_id = None
        self.session_id = None
        self.agents_active = None

    def purge(self, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while self.window and self.window[0][0] < cutoff:
            self.total -= self.window.popleft()[1]
        while self.folder_events and self.folder_events[0] < cutoff:
            self.folder_events.popleft()
        if len(self.dirs_seen) > 5000:
            self.dirs_seen = {d: t for d, t in self.dirs_seen.items() if t >= cutoff}


class MassDeleteDetector:
    def __init__(self):
        self._lock = threading.Lock()
        self._roots: list[tuple[str, str]] = []       # (normalised, display)
        self._roots_at = 0.0
        self._state: dict[str, _Root] = {}
        self._spawns: deque = deque(maxlen=300)       # (ts, pid, name, agent)
        self._tasks: set = set()
        self.grace = GRACE_SECONDS

    # ------------------------------------------------------------------ roots
    def set_roots(self, roots: list[str]) -> None:
        with self._lock:
            self._roots = sorted(((_norm(r), r) for r in roots if r), key=lambda x: -len(x[0]))
            self._roots_at = time.time()

    def roots_stale(self) -> bool:
        return time.time() - self._roots_at > ROOTS_REFRESH_SECONDS

    async def refresh_roots(self) -> None:
        self._roots_at = time.time()      # first, so a slow read is not repeated by every event meanwhile
        try:
            from core.scope_store import get_scope_directories
            from db.database import get_read_db

            db = await get_read_db()
            try:
                roots = await get_scope_directories(db)
            finally:
                await db.close()
            self.set_roots(roots)
        except Exception:
            logger.exception("mass_delete: could not read the watched folders; keeping the last list")

    def _root_for(self, norm_path: str):
        for key, display in self._roots:
            if norm_path == key or norm_path.startswith(key + "/"):
                return key, display
        return None

    # ------------------------------------------------------------------ input
    def note_spawn(self, name: str, pid: int | None, agent: str | None, cmdline: str | None = None, ts: float | None = None) -> None:
        """A process started under an agent. Kept only if it is a delete tool (by name or in its command line)."""
        text = f"{name or ''} {cmdline or ''}"
        if not DELETE_TOOL.search(text):
            return
        with self._lock:
            self._spawns.append((ts if ts is not None else time.time(), pid, name or "", agent or "an agent"))

    def note_folder_event(self, path: str, ts: float | None = None) -> None:
        """The watcher saw a folder deleted (its own is_directory flag). Counted separately, never as a file."""
        norm = _norm(path)
        with self._lock:
            hit = self._root_for(norm)
            if hit is None:
                return
            st = self._state.setdefault(hit[0], _Root(hit[1]))
            st.folder_events.append(ts if ts is not None else time.time())

    def observe(self, event: dict) -> None:
        """Called for every file event before it is buffered. Only deletes count."""
        if event.get("event_type") != "file_delete":
            return
        path = event.get("path") or ""
        norm = _norm(path)
        summary = event.get("summary")
        n = summary["count"] if summary else 1
        now = time.time()
        from core import ignore_rules      # imported here: ignore_rules imports core.aggregator, which imports this module

        if ignore_rules.is_enabled() and ignore_rules.ignored_folder_for(path):
            return
        fire_for = None
        with self._lock:
            hit = self._root_for(norm)
            if hit is None:
                return
            key, display = hit
            st = self._state.setdefault(key, _Root(display))
            st.purge(now)
            if summary:
                st.dirs_seen[norm] = now
                rel_dir = norm
            else:
                if norm in st.dirs_seen:           # files in it went a moment ago: this is the folder itself
                    st.folder_events.append(now)
                    return
                rel_dir = norm.rsplit("/", 1)[0] if "/" in norm else norm
                st.dirs_seen[rel_dir] = now
            rel = rel_dir[len(key) + 1:] if len(rel_dir) > len(key) else ""
            top = rel.split("/")[0] if rel else "(the folder itself)"
            st.window.append((now, n, top))
            st.total += n
            if event.get("agent_id") is not None:
                st.agent_id, st.session_id = event.get("agent_id"), event.get("session_id")
            st.agents_active = event.get("agents_active") or (event.get("detail") or {}).get("agents_active") or st.agents_active
            if st.total >= threshold() and not st.pending and now - st.last_fired >= COOLDOWN_SECONDS and st.agent_id is not None:
                st.pending = True
                fire_for = key
        if fire_for is not None:
            self._schedule(fire_for)

    # ------------------------------------------------------------------ alert
    def _schedule(self, key: str) -> None:
        try:
            task = asyncio.get_running_loop().create_task(self._fire(key))
        except RuntimeError:
            with self._lock:
                self._state[key].pending = False
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def wait_idle(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def _fire(self, key: str) -> None:
        try:
            if self.grace:
                await asyncio.sleep(self.grace)
            now = time.time()
            with self._lock:
                st = self._state[key]
                st.purge(now)
                count = st.total
                if count < threshold():
                    st.pending = False
                    return
                first_ts, last_ts = st.window[0][0], st.window[-1][0]
                tops = Counter()
                for _ts, n, top in st.window:
                    tops[top] += n
                folders_seen = len(st.folder_events)
                agent_id, session_id, agents_active, display = st.agent_id, st.session_id, st.agents_active, st.display
                st.last_fired = now
                spawn = next((s for s in self._spawns if first_ts - 5 <= s[0] <= now), None)

            span = max(1, int(round(last_ts - first_ts)))
            folders = ", ".join(f"{name} ({n})" for name, n in tops.most_common(5))
            agents = f"{agents_active} agents were running" if agents_active else "which agent was running was not recorded for these changes"
            if spawn:
                process = (f"A {spawn[2]} process (pid {spawn[1]}) was seen starting under {spawn[3]} at {_iso(spawn[0])}. "
                           "This is a possible link, medium confidence, not verified: Vigil does not see which process deleted a file.")
            else:
                process = "No process observed that could have deleted these files. Vigil does not see which process deleted a file."
            description = (
                f"{count} files were deleted under {display} between {_iso(first_ts)} and {_iso(last_ts)} ({span} s). "
                f"Top-level folders hit: {folders}. Folder events seen and not counted: {folders_seen}. {agents}. {process}"
            )
            await self._red_lines()._fire(
                agent_id, "mass_delete", "critical",
                title=f"RED LINE: {count} files deleted in {display} within {span} s",
                description=description,
                extra_detail={"root": display, "count": count, "first_ts": _iso(first_ts), "last_ts": _iso(last_ts),
                              "top_folders": dict(tops.most_common(5)), "folder_events": folders_seen,
                              "agents_active": agents_active, "process_observed": bool(spawn)},
                target=display, session_id=session_id,
            )
        except Exception:
            logger.exception("mass_delete: could not write the alert for %s", key)
        finally:
            with self._lock:
                st = self._state.get(key)
                if st is not None:
                    st.pending = False

    _red = None

    def _red_lines(self):
        if self._red is None:
            from core.red_lines import RedLines

            self._red = RedLines()
        return self._red

    def reset(self) -> None:
        """For tests."""
        with self._lock:
            self._state.clear()
            self._spawns.clear()
            self._roots = []
            self._roots_at = 0.0
        self._red = None
        self.grace = GRACE_SECONDS


detector = MassDeleteDetector()
