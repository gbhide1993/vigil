"""Maps OS-level signals (PID, network destination) to the agent that
caused them. This is the core of V-LAW's per-agent attribution."""

import json
import sqlite3
import time

import psutil

from core.alerter import Alerter
from core.behaviour_detector import AGENT_LIKE_THRESHOLD, BehaviourDetector
from core.sessions import SessionManager
from db.database import DB_PATH, get_db

KNOWN_AGENTS = {
    "claude_code": [
        "claude",
        "claude-code",
        "claude_code",
        "claude-cli",
    ],
    "cursor": [
        "Cursor",
        "cursor_ui",
        "cursor-server",
        "cursor-agent",
    ],
    "copilot": [
        "GitHub.Copilot",
        "copilot-agent",
        "copilot-language-server",
        "gh-copilot",
    ],
    "codex": [
        "codex",
        "codex-cli",
        "openai-codex",
    ],
    "agentforce": [
        "salesforce-agent",
        "agentforce",
    ],
}

# Network destination -> agent mapping fallback
# NOTE: Cursor and Codex CLI both talk to api.openai.com. Process-name
# attribution (see KNOWN_AGENTS / _walk_parent_chain) always takes priority
# over this table; this fallback only applies when process attribution
# returns None. api.openai.com is mapped to "cursor" as the default for that
# ambiguous case since Cursor has much higher adoption than Codex CLI today.
# TODO: refine via User-Agent or request-path inspection to disambiguate.
KNOWN_DESTINATIONS = {
    # Claude Code
    "api.anthropic.com":        "claude_code",
    "claude.ai":                "claude_code",
    # Cursor (proxies OpenAI) — also covers Codex CLI ambiguity, see note above
    "api.openai.com":           "cursor",
    "cursor.sh":                "cursor",
    "api2.cursor.sh":           "cursor",
    # GitHub Copilot
    "api.github.com":           "copilot",
    "copilot-proxy.githubusercontent.com": "copilot",
    "githubcopilot.microsoft.com": "copilot",
    # Agentforce
    "api.salesforce.com":       "agentforce",
}

# A PID's parent chain doesn't change between polls unless the process
# itself changes (i.e. the PID is reused for a new process) — walking up
# to 10 parent levels via psutil.Process().parent() on every poll for a
# still-running PID is wasted work, and was the dominant remaining cost
# once ProcessWatcher.poll/NetworkWatcher.poll stopped blocking the event
# loop directly (~4s for ~109 connections, measured on a real dev machine).
# TTL is a memory-growth safeguard for dead PIDs, not a correctness window
# — process identity itself doesn't expire. Same TTL + size-cap cleanup
# shape as core.red_lines._purge_stale_pending_config_writes.
#
# Third tuple element is the behaviour-detector confidence score behind a
# cached "unidentified_agent" result (None otherwise) — see
# Attributor._score_behaviour / get_behaviour_score_for_pid.
_agent_attribution_cache: dict[int, tuple[str | None, float | None, float]] = {}
ATTRIBUTION_CACHE_TTL_SECONDS = 30
ATTRIBUTION_CACHE_MAX_ENTRIES = 2000


def _purge_stale_attribution_cache() -> None:
    """TTL + size-cap cleanup for _agent_attribution_cache. Called on every
    get_agent_for_pid so the dict never grows unbounded over a long-running
    session (many short-lived PIDs) without needing its own scheduler job."""
    now = time.time()
    stale_pids = [
        pid for pid, (_, _score, cached_at) in list(_agent_attribution_cache.items())
        if now - cached_at > ATTRIBUTION_CACHE_TTL_SECONDS
    ]
    for pid in stale_pids:
        _agent_attribution_cache.pop(pid, None)

    if len(_agent_attribution_cache) > ATTRIBUTION_CACHE_MAX_ENTRIES:
        oldest_first = sorted(list(_agent_attribution_cache.items()), key=lambda kv: kv[1][2])
        overflow = len(_agent_attribution_cache) - ATTRIBUTION_CACHE_MAX_ENTRIES
        for pid, _ in oldest_first[:overflow]:
            _agent_attribution_cache.pop(pid, None)


class Attributor:
    def __init__(self):
        self.alerter = Alerter()
        self.sessions = SessionManager()
        self.behaviour_detector = BehaviourDetector()

    def get_agent_for_pid(self, pid: int) -> str | None:
        """Match a PID to a known agent by process name, walking up the
        parent chain if the direct process isn't a known agent binary. If
        that fails, falls back to scoring the PID's recent OS-level
        behaviour (see _score_behaviour) — a process nothing in
        KNOWN_AGENTS recognizes but that behaves like an agent (rapid,
        clustered file/process activity) is attributed to
        "unidentified_agent" instead of being missed entirely.

        Cached per-PID (see _agent_attribution_cache above) since a PID's
        parent chain and name are immutable for the process's lifetime —
        only the TTL bounds cache memory for PIDs that have since exited;
        for a still-running PID the TTL just controls how often the
        (cheap but non-free) behavioural fallback re-checks it."""
        _purge_stale_attribution_cache()

        now = time.time()
        cached = _agent_attribution_cache.get(pid)
        if cached is not None:
            agent, _score, cached_at = cached
            if now - cached_at < ATTRIBUTION_CACHE_TTL_SECONDS:
                return agent

        agent = self._walk_parent_chain(pid)
        score = None
        if agent is None:
            agent, score = self._score_behaviour(pid)

        _agent_attribution_cache[pid] = (agent, score, now)
        return agent

    def get_named_agent_for_pid(self, pid: int) -> str | None:
        """Like get_agent_for_pid, but never triggers the behavioural
        fallback (_score_behaviour) — name-match only, via the cache or
        _walk_parent_chain. For broad sweeps over most/all of the system's
        running processes (see file_watcher.py's _find_owning_agent_pid,
        called on every file event to find "whichever known agent is
        currently active"), where scoring every uninteresting pid's recent
        behaviour on every single call would be pure overhead — often
        hundreds of pids, most already resolved to "no known agent" by
        name, each now costing a synchronous DB round trip they didn't
        before behavioural detection existed. The DB-backed fallback is
        only worth its cost for a single already-of-interest pid (a fresh
        spawn, a connection, an ETW event), which is what get_agent_for_pid
        is for.

        Deliberately does not write to _agent_attribution_cache on a miss —
        only get_agent_for_pid does that, since a cache hit is expected to
        mean "both the name check AND the behavioural check already ran for
        this pid". Caching a name-only "None" here under the same key would
        wrongly suppress a later, real behavioural check for that pid."""
        _purge_stale_attribution_cache()

        cached = _agent_attribution_cache.get(pid)
        if cached is not None:
            agent, _score, cached_at = cached
            if time.time() - cached_at < ATTRIBUTION_CACHE_TTL_SECONDS:
                return agent

        return self._walk_parent_chain(pid)

    def get_behaviour_score_for_pid(self, pid: int) -> float | None:
        """The behaviour-detector confidence score behind a cached
        "unidentified_agent" attribution for `pid`, if any — read by
        process_watcher.py to include the score in the alert it fires for
        that PID. None if `pid` isn't cached, or was attributed by name
        rather than behaviour."""
        cached = _agent_attribution_cache.get(pid)
        return cached[1] if cached is not None else None

    def _score_behaviour(self, pid: int) -> tuple[str | None, float | None]:
        """Fallback for a PID _walk_parent_chain couldn't match by name:
        scores its recent OS-level behaviour via BehaviourDetector. Reads
        through a short-lived, read-only, synchronous sqlite3 connection
        rather than the app's async aiosqlite handle (see
        core.behaviour_detector's module docstring for why) — this method
        must stay synchronous since get_agent_for_pid is called both from
        watcher threads in the executor pool (no event loop to await
        against there) and directly from async code.

        Never raises — any failure here (DB unreachable, bad data) just
        falls back to "no agent", never crashes the caller (ProcessWatcher/
        NetworkWatcher/file_watcher, all of which call get_agent_for_pid
        on every poll)."""
        try:
            db_uri = DB_PATH.resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(db_uri, uri=True, timeout=1)
            conn.row_factory = sqlite3.Row
            try:
                recent_events = self.behaviour_detector.get_recent_events_for_pid(pid, conn)
            finally:
                conn.close()
            score = self.behaviour_detector.score_process(pid, recent_events)
        except Exception:
            return None, None

        if score >= AGENT_LIKE_THRESHOLD:
            return "unidentified_agent", score
        return None, score

    def _walk_parent_chain(self, pid: int) -> str | None:
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        current = proc
        depth = 0
        while current is not None and depth < 10:
            name = current.name()
            for agent_key, process_names in KNOWN_AGENTS.items():
                if any(pn.lower() in name.lower() for pn in process_names):
                    return agent_key
            try:
                current = current.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                current = None
            depth += 1

        return None

    def get_agent_for_destination(self, dest: str) -> str | None:
        """Match a network destination host to a known agent."""
        return KNOWN_DESTINATIONS.get(dest)

    async def get_or_create_agent(self, name: str, pid: int | None = None, confidence: float | None = None) -> int:
        """Return agent_id from DB, creating the row if this is the first
        time we've seen this agent. New agents default to approved=0
        (pending) and fire a CRITICAL alert if not on the approved list.

        `confidence` is the behaviour-detector score behind this call when
        name == "unidentified_agent" (see Attributor.get_behaviour_score_for_pid)
        — passed through to the unapproved-agent alert so it's clear the
        agent was flagged by behaviour, not by a known process name.
        Ignored for every other agent name."""
        db = await get_db()

        cur = await db.execute("SELECT id FROM agents WHERE name = ?", (name,))
        row = await cur.fetchone()

        if row is not None:
            await db.execute(
                "UPDATE agents SET last_seen = CURRENT_TIMESTAMP, pid = ? WHERE id = ?",
                (pid, row["id"]),
            )
            await db.commit()
            return row["id"]

        is_approved = await self._is_approved_agent(db, name)

        cur = await db.execute(
            """
            INSERT INTO agents (name, process_name, pid, approved)
            VALUES (?, ?, ?, ?)
            """,
            (name, name, pid, 1 if is_approved else 0),
        )
        await db.commit()
        agent_id = cur.lastrowid

        if not is_approved:
            await self._fire_unapproved_agent_alert(db, agent_id, name, pid, confidence)

        return agent_id

    async def _is_approved_agent(self, db, name: str) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'approved_agents'"
        )
        row = await cur.fetchone()
        if row is None:
            return False
        approved = json.loads(row["policy_value"])
        return name in approved

    async def _fire_unapproved_agent_alert(
        self, db, agent_id: int, name: str, pid: int | None = None, confidence: float | None = None,
    ) -> None:
        cur = await db.execute(
            "SELECT id FROM alerts WHERE agent_id = ? AND severity = 'critical' AND status = 'open'",
            (agent_id,),
        )
        if await cur.fetchone() is not None:
            return

        extra_detail = {"name": name}
        description = (
            f"{name} (PID {pid}) is running and accessing your file system. "
            "This agent is not on the approved list. Review and approve or block below."
        )
        if name == "unidentified_agent" and confidence is not None:
            extra_detail["behaviour_detected"] = True
            extra_detail["confidence"] = confidence
            description = (
                f"An unidentified process (PID {pid}) is running and accessing your file "
                f"system. It doesn't match any known agent by name, but its behaviour scored "
                f"{confidence:.2f} against V-LAW's agent-likeness signals. Review and approve "
                "or block below."
            )

        await self.alerter.fire_alert(
            agent_id,
            "critical",
            title=f"Unapproved agent detected: {name}",
            description=description,
            reason="unapproved_agent",
            extra_detail=extra_detail,
        )
