"""The mass_delete red line (core/mass_delete.py): per watched folder, a sliding 10 s count of deleted files fed at
ingress. See conftest.py for why VLAW_DATA_DIR is set there."""

import uuid

import pytest
import pytest_asyncio

import db.database as database
from core import mass_delete, watch_stats
from core.aggregator import Aggregator

ROOT = "C:/work/proj"
_created: dict = {"agents": [], "sessions": []}


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.delenv("VLAW_MASS_DELETE_THRESHOLD", raising=False)
    database._db = None
    conn = await database.get_db()
    watch_stats.reset()
    mass_delete.detector.reset()
    mass_delete.detector.set_roots([ROOT])
    mass_delete.detector.grace = 0
    _created["agents"].clear()
    _created["sessions"].clear()
    yield conn
    for sid in _created["sessions"]:
        await conn.execute("DELETE FROM events WHERE session_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (sid,))
        await conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    for agent_id in _created["agents"]:
        await conn.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    await conn.commit()
    mass_delete.detector.reset()
    watch_stats.reset()      # a leftover count would add a line to every later report (test_network_monitoring_status)
    await database.close_db()


async def _agent_and_session(db):
    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"md_{uuid.uuid4().hex[:8]}",))
    agent_id = cur.lastrowid
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (sid, agent_id))
    await db.commit()
    _created["agents"].append(agent_id)
    _created["sessions"].append(sid)
    return agent_id, sid


def _aggregator():
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    return agg


def _delete(agent_id, sid, path, **extra):
    return {"agent_id": agent_id, "session_id": sid, "event_type": "file_delete", "path": path, "event_source": "realtime_heuristic",
            "attribution_confidence": "low", "change": "delete", "timestamp": 1_800_000_000.0, **extra}


async def _alerts(db, agent_id):
    cur = await db.execute("SELECT * FROM alerts WHERE agent_id = ? AND reason = 'red_line_mass_delete'", (agent_id,))
    return [dict(r) for r in await cur.fetchall()]


async def _feed(agg, agent_id, sid, n, folder="d", ext=".txt", base=ROOT, **extra):
    for i in range(n):
        await agg.ingest_file_event(_delete(agent_id, sid, f"{base}/{folder}{i % 30}/f{i}{ext}", **extra))
    await mass_delete.detector.wait_idle()


def test_the_default_threshold_is_three_times_the_baseline_and_the_env_var_overrides_it(monkeypatch):
    monkeypatch.delenv("VLAW_MASS_DELETE_THRESHOLD", raising=False)
    assert mass_delete.threshold() == max(150, 3 * 301) == 903
    monkeypatch.setenv("VLAW_MASS_DELETE_THRESHOLD", "40")
    assert mass_delete.threshold() == 40
    monkeypatch.setenv("VLAW_MASS_DELETE_THRESHOLD", "not a number")
    assert mass_delete.threshold() == 903


@pytest.mark.asyncio
async def test_200_deletes_in_a_watched_root_raise_no_alert(db):
    agent_id, sid = await _agent_and_session(db)
    await _feed(_aggregator(), agent_id, sid, 200)
    assert await _alerts(db, agent_id) == []


@pytest.mark.asyncio
async def test_3000_deletes_raise_exactly_one_critical_red_line_alert(db):
    agent_id, sid = await _agent_and_session(db)
    agg = _aggregator()
    await _feed(agg, agent_id, sid, 3000, agents_active=2)
    await _feed(agg, agent_id, sid, 3000, agents_active=2)     # a second burst inside the minute: still one
    alerts = await _alerts(db, agent_id)
    assert len(alerts) == 1
    (alert,) = alerts
    assert alert["severity"] == "critical" and alert["rule_type"] == "red_line" and alert["target"] == ROOT
    text = alert["description"]
    assert "files were deleted under C:/work/proj" in text and "UTC" in text
    assert "Top-level folders hit: d" in text and "2 agents were running" in text
    assert "No process observed" in text
    assert "certain" not in text.lower() and "confirmed" not in text.lower()
    assert 903 <= int(alert["title"].split()[2]) <= 6000


@pytest.mark.asyncio
async def test_deleting_3000_files_in_an_ignored_folder_raises_no_alert(db):
    agent_id, sid = await _agent_and_session(db)
    await _feed(_aggregator(), agent_id, sid, 3000, folder="node_modules/pkg", ext=".js")
    assert await _alerts(db, agent_id) == []


@pytest.mark.asyncio
async def test_a_summary_row_counts_for_every_change_it_stands_for(db):
    agent_id, sid = await _agent_and_session(db)
    agg = _aggregator()
    await agg.ingest_file_event(_delete(agent_id, sid, f"{ROOT}/d1", summary={"count": 3000, "first_ts": 1.0, "last_ts": 2.0, "confidence": "low"}))
    await mass_delete.detector.wait_idle()
    (alert,) = await _alerts(db, agent_id)
    assert alert["title"].startswith("RED LINE: 3000 files deleted")


@pytest.mark.asyncio
async def test_folder_events_are_counted_apart_and_not_as_files(db):
    agent_id, sid = await _agent_and_session(db)
    agg = _aggregator()
    for i in range(1000):
        await agg.ingest_file_event(_delete(agent_id, sid, f"{ROOT}/d1/f{i}.txt"))
    await agg.ingest_file_event(_delete(agent_id, sid, f"{ROOT}/d1"))           # the folder itself, reported after its files
    mass_delete.detector.note_folder_event(f"{ROOT}/d2")                        # a folder the watcher flagged as a directory
    await mass_delete.detector.wait_idle()
    (alert,) = await _alerts(db, agent_id)
    assert alert["title"].startswith("RED LINE: 1000 files deleted")
    assert "Folder events seen and not counted: 2" in alert["description"]


@pytest.mark.asyncio
async def test_a_delete_tool_seen_under_an_agent_is_a_possible_link_never_a_certainty(db):
    agent_id, sid = await _agent_and_session(db)
    mass_delete.detector.note_spawn("bash.exe", 4242, "claude_code", 'bash.exe -c "rm -rf proj/build"')
    mass_delete.detector.note_spawn("git.exe", 4243, "claude_code", "git status")          # not a delete tool: ignored
    await _feed(_aggregator(), agent_id, sid, 1000)
    (alert,) = await _alerts(db, agent_id)
    assert "bash.exe process (pid 4242)" in alert["description"] and "medium confidence, not verified" in alert["description"]
    assert "No process observed" not in alert["description"] and "4243" not in alert["description"]


@pytest.mark.asyncio
async def test_deletes_outside_every_watched_root_and_other_events_do_not_count(db):
    agent_id, sid = await _agent_and_session(db)
    agg = _aggregator()
    await _feed(agg, agent_id, sid, 2000, base="C:/elsewhere")
    for i in range(2000):
        await agg.ingest_file_event({**_delete(agent_id, sid, f"{ROOT}/d/f{i}.txt"), "event_type": "file_write"})
    await mass_delete.detector.wait_idle()
    assert await _alerts(db, agent_id) == []
