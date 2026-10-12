"""Running, open (idle) and active are different things; a background helper that has been
open for days is not "in progress", and a process Vigil already recorded is not recorded
again after a restart."""

import json
import random
import subprocess
import time
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio

import api.agents as agents_module
import core.agent_activity as agent_activity
import core.runtime_state as runtime_state
import db.database as database
from watchers.process_watcher import ProcessWatcher, already_recorded

ROOT = Path(__file__).resolve().parents[2]


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


def _ts(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%d %H:%M:%S")


async def _agent(db, label="activity_agent"):
    name = f"{label}_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, ?, 1)", (name, name))
    await db.commit()
    return cur.lastrowid, name


async def _event(db, agent_id, event_type, seconds_ago, detail=None, path="x", pid=None):
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail, created_at, pid) VALUES (?, 'sess-activity', ?, ?, ?, ?, ?)",
        (agent_id, event_type, path, json.dumps(detail or {}), _ts(seconds_ago), pid),
    )


async def _cleanup(db, *agent_ids):
    for agent_id in agent_ids:
        await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
    await db.commit()


# ------------------------------------------------------------- already_recorded

def test_same_pid_and_creation_time_is_the_same_process():
    rows = [({"process_started": 1_000_000}, "2026-10-12 08:00:00")]
    assert already_recorded(rows, 1_000_000)
    assert already_recorded(rows, 1_000_002), "the two process sources can differ by a second or two"
    assert not already_recorded(rows, 1_000_600), "a later process that reused the pid is new"
    assert not already_recorded([], 1_000_000)


def test_rows_from_before_creation_times_were_stored_are_matched_by_time():
    written = datetime(2026, 10, 12, 8, 0, 0, tzinfo=timezone.utc)
    rows = [({}, "2026-10-12 08:00:00")]
    assert already_recorded(rows, int(written.timestamp()) - 3600), "the process had started before that row was written"
    assert not already_recorded(rows, int(written.timestamp()) + 600), "a process that started later is a different one"
    assert not already_recorded(rows, 0), "unknown creation time is never matched"


# ------------------------------------------------------------- the watcher

class _Sessions:
    async def touch(self, agent_id, resumed=False):
        return "sess-activity"


class _Attributor:
    def __init__(self, db, names):
        self._db = db
        self.sessions = _Sessions()
        self.names = names
        self.agent_ids = {}

    def get_named_agent_for_pid(self, pid, pid_snapshot=None):
        return self.names.get(pid)

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        if name not in self.agent_ids:
            cur = await self._db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, ?, 1)", (f"{name}_{uuid.uuid4().hex[:6]}", name))
            await self._db.commit()
            self.agent_ids[name] = cur.lastrowid
        return self.agent_ids[name]


def _watcher(db, snapshot, names):
    attributor = _Attributor(db, names)
    watcher = ProcessWatcher(attributor, aggregator=None)
    watcher._pid_snapshot = snapshot
    return watcher, attributor


async def _rows(db, pid):
    cur = await db.execute("SELECT detail, created_at FROM events WHERE event_type = 'proc_spawn' AND pid = ?", (pid,))
    return [(json.loads(r["detail"]), r["created_at"]) for r in await cur.fetchall()]


@pytest.mark.asyncio
async def test_a_process_already_recorded_is_not_recorded_again_after_a_restart(db):
    pid = random.randint(5_000_000, 6_000_000)
    started = int(time.time()) - 2 * 86400            # the helper has been open for two days
    snapshot = {pid: {"name": "codex.exe", "ppid": 1, "status": "running", "started": started}}
    agent_ids = []
    try:
        first, attributor = _watcher(db, snapshot, {pid: "codex"})
        await first._poll_write_body({pid})
        agent_ids.append(attributor.agent_ids["codex"])
        rows = await _rows(db, pid)
        assert len(rows) == 1
        assert rows[0][0]["already_running"] is True and rows[0][0]["process_started"] == started
        assert rows[0][0]["activity_spawn"] is False

        for restart in range(3):               # three more restarts of Vigil: nothing new is written
            again, attributor = _watcher(db, snapshot, {pid: "codex"})
            await again._poll_write_body({pid})
            agent_ids.append(attributor.agent_ids.get("codex"))
        assert len(await _rows(db, pid)) == 1

        # the same pid for a different process (it started later) is a new process
        reused = {pid: {"name": "codex.exe", "ppid": 1, "status": "running", "started": started + 86400}}
        later, attributor = _watcher(db, reused, {pid: "codex"})
        later._is_first_poll = False
        await later._poll_write_body({pid})
        agent_ids.append(attributor.agent_ids["codex"])
        rows = await _rows(db, pid)
        assert len(rows) == 2 and "already_running" not in rows[1][0]
    finally:
        await _cleanup(db, *[a for a in agent_ids if a])


@pytest.mark.asyncio
async def test_a_row_written_by_an_older_version_is_not_duplicated(db):
    pid = random.randint(6_000_001, 7_000_000)
    agent_id, _ = await _agent(db)
    await _event(db, agent_id, "proc_spawn", 600, detail={"pid": pid, "command": "codex.exe"}, pid=pid)   # no process_started
    await db.commit()
    snapshot = {pid: {"name": "codex.exe", "ppid": 1, "status": "running", "started": int(time.time()) - 86400}}
    watcher, attributor = _watcher(db, snapshot, {pid: "codex"})
    try:
        await watcher._poll_write_body({pid})
        assert len(await _rows(db, pid)) == 1
    finally:
        await _cleanup(db, agent_id, *attributor.agent_ids.values())


@pytest.mark.asyncio
async def test_only_a_new_tool_process_under_an_agent_counts_as_activity_spawn(db):
    helper, shell, sandbox, other = (random.randint(7_000_001 + i * 1000, 7_000_900 + i * 1000) for i in range(4))
    now = int(time.time())
    snapshot = {
        helper: {"name": "codex.exe", "ppid": 1, "status": "running", "started": now - 86400},
        shell: {"name": "cmd.exe", "ppid": helper, "status": "running", "started": now - 5},
        sandbox: {"name": "codex-windows-sandbox-service.exe", "ppid": helper, "status": "running", "started": now - 5},
    }
    names = {helper: "codex", shell: "codex", sandbox: "codex"}
    watcher, attributor = _watcher(db, snapshot, names)
    watcher._is_first_poll = False
    try:
        await watcher._poll_write_body({helper, shell, sandbox})
        assert (await _rows(db, helper))[0][0]["activity_spawn"] is False, "the long-lived helper itself"
        assert (await _rows(db, shell))[0][0]["activity_spawn"] is True, "a new shell under the agent"
        assert (await _rows(db, sandbox))[0][0]["activity_spawn"] is False, "another process of the agent's own"
        assert watcher.running_agents == {"codex": [helper, shell, sandbox]}
    finally:
        await _cleanup(db, *attributor.agent_ids.values())


# ------------------------------------------------------------- idle versus active

def _watcher_stub(running):
    return types.SimpleNamespace(running_agents=running)


async def _agent_row(agent_id):
    data = await agents_module.get_agents()
    assert data["activity_window_seconds"] == 300
    return next(a for a in data["agents"] if a["id"] == agent_id)


@pytest.mark.asyncio
async def test_a_background_helper_that_is_only_open_is_idle_not_in_progress(db, monkeypatch):
    agent_id, name = await _agent(db)
    monkeypatch.setitem(runtime_state.state, "process_watcher", _watcher_stub({name: [4242]}))
    # The helper's own spawn, long ago and just now; the "already running" marker; an open session's
    # leftovers. None of these is activity.
    await _event(db, agent_id, "proc_spawn", 2 * 86400, detail={"activity_spawn": False, "process_started": 1})
    await _event(db, agent_id, "proc_spawn", 30, detail={"activity_spawn": False, "process_started": 2}, pid=1)
    await _event(db, agent_id, "proc_spawn", 20, detail={"activity_spawn": True, "already_running": True, "process_started": 3}, pid=2)
    await db.commit()
    try:
        row = await _agent_row(agent_id)
        assert row["running"] is True and row["activity"] == "open_idle" and row["current_status"] == "idle"
        assert row["last_activity_at"] is None
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_a_file_change_in_the_last_five_minutes_is_active(db, monkeypatch):
    agent_id, name = await _agent(db)
    monkeypatch.setitem(runtime_state.state, "process_watcher", _watcher_stub({name: [4242]}))
    await _event(db, agent_id, "file_write", 120, path="C:/proj/a.py")
    await db.commit()
    try:
        row = await _agent_row(agent_id)
        assert row["activity"] == "active" and row["current_status"] == "active" and row["last_activity_at"]
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_activity_older_than_five_minutes_no_longer_counts(db, monkeypatch):
    agent_id, name = await _agent(db)
    monkeypatch.setitem(runtime_state.state, "process_watcher", _watcher_stub({name: [4242]}))
    await _event(db, agent_id, "file_write", 330, path="C:/proj/a.py")
    await db.commit()
    try:
        assert (await _agent_row(agent_id))["activity"] == "open_idle"
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_a_new_tool_process_counts_but_other_event_kinds_do_too(db, monkeypatch):
    agent_id, name = await _agent(db)
    other_id, other = await _agent(db, "net")
    monkeypatch.setitem(runtime_state.state, "process_watcher", _watcher_stub({name: [1], other: [2]}))
    await _event(db, agent_id, "proc_spawn", 60, detail={"activity_spawn": True, "process_started": 5}, pid=77)
    await _event(db, other_id, "net_connect", 60, path="api.example.com")
    await db.commit()
    try:
        assert (await _agent_row(agent_id))["activity"] == "active"
        assert (await _agent_row(other_id))["activity"] == "active"
    finally:
        await _cleanup(db, agent_id, other_id)


@pytest.mark.asyncio
async def test_an_agent_with_no_process_is_not_running(db, monkeypatch):
    agent_id, _ = await _agent(db)
    monkeypatch.setitem(runtime_state.state, "process_watcher", _watcher_stub({}))
    try:
        row = await _agent_row(agent_id)
        assert row["running"] is False and row["activity"] == "not_running" and row["current_status"] == "inactive"
    finally:
        await _cleanup(db, agent_id)


def test_classification_rules():
    assert agent_activity.classify(True, None) == "open_idle"
    assert agent_activity.classify(False, None) == "not_running"
    assert agent_activity.classify(True, "2026-10-12 08:00:00") == "active"
    assert agent_activity.classify(False, "2026-10-12 08:00:00") == "active"
    assert agent_activity.ACTIVITY_WINDOW_SECONDS == 300


# ------------------------------------------------------------- tray and sidebar

def _node(script):
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_tray_tooltip_wording():
    out = _node("""
    import { createRequire } from 'node:module'
    const { trayStatusText } = createRequire(import.meta.url)('./tray/status-text.js')
    const a = (name, activity) => ({ name, activity })
    console.log(JSON.stringify({
      nothing: trayStatusText({ agents: [] }),
      notRunning: trayStatusText({ agents: [a('codex', 'not_running')] }),
      idle: trayStatusText({ agents: [a('codex', 'open_idle')] }),
      idleTwo: trayStatusText({ agents: [a('codex', 'open_idle'), a('claude_code', 'open_idle')] }),
      active: trayStatusText({ agents: [a('codex', 'open_idle'), a('claude_code', 'active')] }),
      review: trayStatusText({ agents: [a('codex', 'active')], needsReview: 2 }),
      review1: trayStatusText({ needsReview: 1 }),
    }))
    """)
    assert out["nothing"] == "Vigil: watching" and out["notRunning"] == "Vigil: watching"
    assert out["idle"] == "Vigil: codex open (idle)" and out["idleTwo"] == "Vigil: codex, claude_code open (idle)"
    assert out["active"] == "Vigil: claude_code active", "an idle helper next to a really active agent is not named"
    assert out["review"].endswith("2 alerts need review.") and out["review1"].endswith("1 alert needs review.")


def test_tray_and_sidebar_use_the_backend_definition():
    tray = (ROOT / "tray" / "main.js").read_text(encoding="utf-8")
    assert "trayStatusText" in tray and "session in progress" not in tray and "Live:" not in tray
    package = json.loads((ROOT / "tray" / "package.json").read_text(encoding="utf-8"))
    assert "status-text.js" in package["build"]["files"]
    sidebar = (ROOT / "frontend" / "src" / "components" / "Sidebar.jsx").read_text(encoding="utf-8")
    assert "a.activity === 'active'" in sidebar and "open, idle" in sidebar and "current_status" not in sidebar
    assert "not running" in sidebar
