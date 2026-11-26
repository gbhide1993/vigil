"""Record integrity: an event is never dropped without a record. Bug 1 (buffer overflow becomes summary rows, early
flush) and the session counters of bug 2. See conftest.py for why VLAW_DATA_DIR is set there."""

import asyncio
import json
import types
import uuid

import pytest
import pytest_asyncio

import db.database as database
from core import aggregator as aggregator_module
from core import watch_stats
from core import sessions as sessions_core
from core.aggregator import Aggregator


@pytest.fixture(autouse=True)
def _clean_counters():
    watch_stats.reset()
    yield
    watch_stats.reset()


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    _created["agents"].clear()
    _created["sessions"].clear()
    yield conn
    # the test database is shared by the whole run: leave nothing behind (the evidence chain tests count events)
    for sid in _created["sessions"]:
        await conn.execute("DELETE FROM alerts WHERE session_id = ?", (sid,))
        await conn.execute("DELETE FROM events WHERE session_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (sid,))
        await conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    for agent_id in _created["agents"]:
        await conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    await conn.commit()
    await database.close_db()


_created: dict = {"agents": [], "sessions": []}


async def _agent_and_session(db):
    cur = await db.execute(
        "INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"integrity_{uuid.uuid4().hex[:8]}",)
    )
    agent_id = cur.lastrowid
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (sid, agent_id))
    await db.commit()
    _created["agents"].append(agent_id)
    _created["sessions"].append(sid)
    return agent_id, sid


def _event(agent_id, sid, i, folder=None, event_type="file_delete"):
    folder = folder if folder is not None else f"C:/proj/d{i % 30}"
    return {
        "agent_id": agent_id, "session_id": sid, "event_type": event_type, "path": f"{folder}/f{i}.txt",
        "detail": {"attribution_confidence": "high"}, "severity": "low", "pid": None,
        "event_source": "realtime_heuristic", "timestamp": 1_800_000_000.0 + i,
    }


def _represented(buffer):
    return sum((e["summary"]["count"] if e.get("summary") else 1) for e in buffer)


@pytest.mark.asyncio
async def test_overflow_collapses_the_middle_and_loses_nothing(db):
    """Root cause was aggregator.py buffer_file_event: at 1,000 buffered events it pop(0)-ed the oldest and counted it
    as dropped. Now the middle becomes summary rows; the oldest and newest events stay individual."""
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    total = 3000
    for i in range(total):
        await agg.buffer_file_event(_event(agent_id, sid, i))

    buf = agg.file_event_buffer
    assert len(buf) <= aggregator_module.FILE_EVENT_BUFFER_MAX
    assert _represented(buf) == total, "every event is an individual row or counted inside a summary row"
    assert watch_stats.dropped_total() == 0
    assert watch_stats.summarised_total() > 0

    keep = aggregator_module.FILE_EVENT_KEEP_OLDEST
    assert [e["path"] for e in buf[:keep]] == [f"C:/proj/d{i % 30}/f{i}.txt" for i in range(keep)], "the oldest stay individual"
    newest = aggregator_module.FILE_EVENT_KEEP_NEWEST
    assert [e["path"] for e in buf[-newest:]] == [f"C:/proj/d{i % 30}/f{i}.txt" for i in range(total - newest, total)]
    summaries = [e for e in buf if e.get("summary")]
    assert summaries and not any(e.get("summary") for e in buf[:keep]), "summaries sit after the oldest block"
    for e in summaries:
        s = e["summary"]
        assert s["count"] >= 1 and s["first_ts"] <= s["last_ts"]
        assert e["event_type"] == "file_delete" and e["path"].replace("\\", "/").startswith("C:/proj/d")


@pytest.mark.asyncio
async def test_summary_rows_are_written_with_their_count_and_counted_per_session(db):
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    agg._writer_task = asyncio.create_task(agg.start_writer())
    try:
        total = 2500
        for i in range(total):
            await agg.buffer_file_event(_event(agent_id, sid, i))
        await agg._flush_file_event_buffer()
        assert agg.file_event_buffer == []
    finally:
        await agg.stop_writer()

    cur = await db.execute("SELECT COALESCE(SUM(file_count), 0) AS n, COUNT(*) AS rows_ FROM events WHERE session_id = ?", (sid,))
    row = await cur.fetchone()
    assert row["n"] == total and row["rows_"] < total
    cur = await db.execute("SELECT detail, path, file_count FROM events WHERE session_id = ? AND json_extract(detail, '$.summary') = 1", (sid,))
    summaries = await cur.fetchall()
    assert summaries
    detail = json.loads(summaries[0]["detail"])
    assert detail["operation"] == "file_delete" and detail["count"] == summaries[0]["file_count"]
    assert detail["first_ts"] <= detail["last_ts"] and summaries[0]["path"].replace("\\", "/").startswith("C:/proj/d")


@pytest.mark.asyncio
async def test_the_buffer_flushes_early_at_eighty_percent_without_the_timer(db):
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._writer_task = asyncio.create_task(agg.start_writer())
    try:
        for i in range(aggregator_module.FILE_EVENT_EARLY_FLUSH_AT - 1):
            await agg.buffer_file_event(_event(agent_id, sid, i))
        assert agg._early_flush_task is None, "below 80% nothing flushes by itself"
        await agg.buffer_file_event(_event(agent_id, sid, 9999))
        assert agg._early_flush_task is not None
        await agg._early_flush_task
    finally:
        await agg.stop_writer()
    cur = await db.execute("SELECT COUNT(*) AS n FROM events WHERE session_id = ?", (sid,))
    assert (await cur.fetchone())["n"] == aggregator_module.FILE_EVENT_EARLY_FLUSH_AT
    assert agg.file_event_buffer == [] and watch_stats.dropped_total() == 0


@pytest.mark.asyncio
async def test_events_arriving_during_a_write_are_kept_and_the_written_prefix_is_never_collapsed(db):
    """The flush deletes exactly the prefix it wrote; a collapse must never reorder or merge that prefix."""
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    for i in range(50):
        await agg.buffer_file_event(_event(agent_id, sid, i))
    agg._flushing = 50          # a write of these 50 is in flight
    prefix = list(agg.file_event_buffer[:50])
    for i in range(50, 50 + 3000):
        await agg.buffer_file_event(_event(agent_id, sid, i))
    assert agg.file_event_buffer[:50] == prefix
    assert _represented(agg.file_event_buffer) == 3050 and watch_stats.dropped_total() == 0


@pytest.mark.asyncio
async def test_a_second_flush_while_one_is_in_flight_does_not_write_twice(db):
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    agg._writer_task = asyncio.create_task(agg.start_writer())
    try:
        for i in range(100):
            await agg.buffer_file_event(_event(agent_id, sid, i))
        await asyncio.gather(agg._flush_file_event_buffer(), agg._flush_file_event_buffer(), agg._flush_file_event_buffer())
    finally:
        await agg.stop_writer()
    cur = await db.execute("SELECT COUNT(*) AS n FROM events WHERE session_id = ?", (sid,))
    assert (await cur.fetchone())["n"] == 100


def test_health_reports_summarised_and_dropped_separately():
    watch_stats.add_summarised(7)
    summary = watch_stats.summary()
    assert summary["summarised_total"] == 7 and summary["dropped_total"] == 0
    watch_stats.add_dropped("overload")
    assert watch_stats.summary()["dropped_total"] == 1


# ------------------------------------------------------------------ bug 2: session counters

async def _row(db, agent_id, sid, event_type, path, count=1, detail=None):
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count, detail, event_source) "
        "VALUES (?, ?, ?, ?, ?, ?, 'realtime_heuristic')",
        (agent_id, sid, event_type, path, count, json.dumps(detail or {})),
    )


@pytest.mark.asyncio
async def test_an_rm_rf_session_shows_its_deletes_and_its_writes_separately_while_still_open(db):
    """Root cause: core/sessions.py _roll_up_session_stats counted only event_type = 'file_write' and only ran when a
    session closed (the idle sweep is off), so an open session full of file_delete rows read file_writes = 0."""
    import api.sessions as sessions_api

    sessions_core._aggregates.update(key=None, max_id=0, count=0, by_session={})
    agent_id, sid = await _agent_and_session(db)
    for i in range(400):
        await _row(db, agent_id, sid, "file_delete", f"C:/proj/d{i % 30}/f{i}.txt")
    await _row(db, agent_id, sid, "file_delete", "C:/proj/d1", count=600, detail={"summary": True, "count": 600})
    for i in range(5):
        await _row(db, agent_id, sid, "file_write", f"C:/proj/new{i}.txt")
    await db.commit()

    listed = {s["id"]: s for s in (await sessions_api.get_sessions())["sessions"]}[sid]
    assert listed["ended_at"] is None, "the session is still open: nothing rolled its columns up"
    assert listed["file_deletes"] == 1000 and listed["file_writes"] == 5
    assert listed["events_summarised"] == 600 and listed["events_dropped"] == 0


@pytest.mark.asyncio
async def test_directory_events_are_not_recorded_as_writes(db, monkeypatch):
    import watchers.file_watcher as file_watcher

    def never(coro, loop):
        coro.close()
        raise AssertionError("a directory event must not be dispatched")

    monkeypatch.setattr(file_watcher.asyncio, "run_coroutine_threadsafe", never)
    handler = file_watcher.VlawFileHandler(object(), object(), asyncio.get_running_loop(), pid_cache=None)
    for kind in ("modified", "created", "deleted"):
        handler.on_any_event(types.SimpleNamespace(is_directory=True, event_type=kind, src_path="C:/proj/src", dest_path=""))
    assert watch_stats.dropped_total() == 0


@pytest.mark.asyncio
async def test_the_session_report_counts_summaries_and_prints_the_line(db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas
    from unittest.mock import patch

    import api.sessions as sessions_api

    agent_id, sid = await _agent_and_session(db)
    await _row(db, agent_id, sid, "file_delete", "C:/proj/a.txt")
    await _row(db, agent_id, sid, "file_delete", "C:/proj/d1", count=600,
               detail={"summary": True, "count": 600, "first_ts": "2026-11-23 10:00:00", "last_ts": "2026-11-23 10:00:30"})
    await db.commit()

    report = await sessions_api._build_session_report(sid)
    assert report["file_changes_total"] == 601 and report["file_changes_by_type"] == {"delete": 601}
    assert report["events_summarised"] == 600 and report["events_dropped"] == 0
    assert report["files_touched_count"] == 1, "a summary row is a directory with a count, not a file"

    app = FastAPI()
    app.include_router(sessions_api.router)
    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text, *a, **k):
        drawn.append(text)
        return original(self, x, y, text, *a, **k)

    with patch.object(canvas.Canvas, "drawString", capture):
        assert TestClient(app).get(f"/sessions/{sid}/report").status_code == 200
    assert any("600 events recorded as summaries" in t for t in drawn)
    assert any("600 changes, summarised" in t for t in drawn)
    preview = TestClient(app).get(f"/sessions/{sid}/report/preview").json()
    assert preview["events_summarised"] == 600 and preview["events_dropped"] == 0


# ------------------------------------------------------------------ the watcher's own bound (file_watcher.py)

class _Cache:
    def __init__(self, mapping):
        self.mapping = mapping

    def snapshot(self):
        return self.mapping


class _Recorder:
    def __init__(self):
        self.calls = []

    async def ingest_file_event(self, event):
        self.calls.append(event)


class _Attributor:
    def __init__(self, names, agent_id=99, session_id="sess"):
        self.names, self.agent_id, self.session_id = names, agent_id, session_id

        class sessions:
            @staticmethod
            async def touch(agent_id, resumed=False):
                return session_id

        self.sessions = sessions

    def get_agent_for_pid(self, pid):
        return self.names.get(pid)

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        return self.agent_id

    async def get_or_create_unattributed_agent(self):
        return self.agent_id


def _handler(names, aggregator, agent_id=99, session_id="sess"):
    import watchers.file_watcher as file_watcher

    return file_watcher.VlawFileHandler(
        _Attributor(names, agent_id, session_id), aggregator, asyncio.new_event_loop(), pid_cache=_Cache(names), use_pid_heuristic=True
    )


@pytest.mark.asyncio
async def test_overflow_is_recorded_as_summary_rows_per_directory_and_nothing_is_lost(db):
    """Root cause 2 of bug 1: watchers/file_watcher.py on_any_event dropped (and only counted) every raw event over
    MAX_PENDING_FILE_DISPATCH, before the aggregator ever saw it. Now they are counted per directory and recorded."""
    recorder = _Recorder()
    handler = _handler({10: "codex", 20: "claude_code"}, recorder)
    for i in range(7):
        handler._count_overflow(f"C:/proj/a/f{i}.txt", "file_delete", "delete")
    for i in range(5):
        handler._count_overflow(f"C:/proj/b/f{i}.txt", "file_delete", "delete")
    await handler.drain_overflow()

    assert handler._overflow == {} and watch_stats.dropped_total() == 0
    got = {e["path"].replace("\\", "/"): e for e in recorder.calls}
    assert set(got) == {"C:/proj/a", "C:/proj/b"}
    assert got["C:/proj/a"]["summary"]["count"] == 7 and got["C:/proj/b"]["summary"]["count"] == 5
    for e in got.values():
        assert e["event_type"] == "file_delete" and e["change"] == "delete"
        assert e["summary"]["first_ts"] <= e["summary"]["last_ts"]
        assert e["attribution_confidence"] == "low" and e["agents_active"] == 2, "two agents running: still not credited to one"


@pytest.mark.asyncio
async def test_a_credential_path_is_never_folded_into_a_count(db, monkeypatch):
    import watchers.file_watcher as file_watcher

    dispatched = []

    def fake_submit(coro, loop):
        coro.close()
        dispatched.append(1)
        return types.SimpleNamespace(add_done_callback=lambda cb: None)

    monkeypatch.setattr(file_watcher.asyncio, "run_coroutine_threadsafe", fake_submit)
    monkeypatch.setattr(file_watcher, "MAX_PENDING_FILE_DISPATCH", 0)
    handler = _handler({10: "claude_code"}, _Recorder())
    handler.on_any_event(types.SimpleNamespace(is_directory=False, event_type="modified", src_path="C:/proj/.env", dest_path=""))
    handler.on_any_event(types.SimpleNamespace(is_directory=False, event_type="deleted", src_path="C:/proj/src/a.py", dest_path=""))
    assert len(dispatched) == 1, "the .env change went through; the ordinary one was counted"
    assert sum(g["count"] for g in handler._overflow.values()) == 1


@pytest.mark.asyncio
async def test_overflow_end_to_end_the_database_holds_every_change(db):
    agent_id, sid = await _agent_and_session(db)
    agg = Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    agg._start_early_flush = lambda: None
    agg._writer_task = asyncio.create_task(agg.start_writer())
    handler = _handler({20: "claude_code"}, agg, agent_id, sid)
    try:
        for i in range(1200):
            handler._count_overflow(f"C:/proj/d{i % 30}/f{i}.txt", "file_delete", "delete")
        await handler.drain_overflow()
        await agg._flush_file_event_buffer()
    finally:
        await agg.stop_writer()
    cur = await db.execute("SELECT COALESCE(SUM(file_count), 0) AS n FROM events WHERE session_id = ? AND event_type = 'file_delete'", (sid,))
    assert (await cur.fetchone())["n"] == 1200
    assert watch_stats.dropped_total() == 0 and watch_stats.summarised_total() == 1200
    cur = await db.execute("SELECT COUNT(*) AS n FROM events WHERE session_id = ? AND json_extract(detail, '$.summary') = 1", (sid,))
    assert (await cur.fetchone())["n"] == 30
