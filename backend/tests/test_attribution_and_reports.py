"""Honest attribution for the native observer, and the file-change content of
the session and daily reports. See conftest.py for why VLAW_DATA_DIR is set
there rather than here."""

import asyncio
import json
import shutil
import subprocess
import types
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio

import api.events as events_module
import api.export as export_module
import api.sessions as sessions_module
import core.scope_store as scope_store
import db.database as database
import watchers.file_watcher as file_watcher
from core import watch_stats
from core.attribution import attribution_for
from core.file_changes import change_type, scope_label, summarise, utc_iso
from core.monitoring_status import set_file_watcher_tier

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _reset():
    watch_stats.reset()
    yield
    watch_stats.reset()
    set_file_watcher_tier("folders")


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    cur = await conn.execute(
        "SELECT policy_key, policy_value FROM policy WHERE policy_key IN (?, ?)",
        (scope_store.SCOPE_KEY, scope_store.META_KEY),
    )
    saved = {r["policy_key"]: r["policy_value"] for r in await cur.fetchall()}
    await conn.execute("DELETE FROM policy WHERE policy_key IN (?, ?)", (scope_store.SCOPE_KEY, scope_store.META_KEY))
    await conn.commit()
    yield conn
    await conn.execute("DELETE FROM policy WHERE policy_key IN (?, ?)", (scope_store.SCOPE_KEY, scope_store.META_KEY))
    for key, value in saved.items():
        await conn.execute("INSERT INTO policy (policy_key, policy_value) VALUES (?, ?)", (key, value))
    await conn.commit()
    await database.close_db()


# ------------------------------------------------------ the confidence rule

class _Cache:
    def __init__(self, mapping):
        self.mapping = mapping

    def snapshot(self):
        return self.mapping


@pytest.mark.asyncio
async def test_native_observer_confidence_is_never_high(monkeypatch):
    refined = {"pid": None}

    async def fake_refine(candidates, path):
        return refined["pid"]

    monkeypatch.setattr(file_watcher, "_refine_pid_by_open_handle", fake_refine)
    find = file_watcher._find_owning_agent_pid

    # no agent running: nothing to attribute to (the caller drops the event)
    assert await find(_Cache({}), "C:/p/a.py") == (None, "low")
    # one agent, one process: an agent was running, the writer was not verified
    assert await find(_Cache({10: "claude_code"}), "C:/p/a.py") == (10, "medium")
    # one agent, several processes, no open handle found
    assert await find(_Cache({10: "claude_code", 11: "claude_code"}), "C:/p/a.py") == (10, "medium")
    # one agent, several processes, the open-handle check names one: still not "high"
    refined["pid"] = 11
    assert await find(_Cache({10: "claude_code", 11: "claude_code"}), "C:/p/a.py") == (11, "medium")
    # more than one agent running
    refined["pid"] = None
    assert await find(_Cache({10: "claude_code", 20: "codex"}), "C:/p/a.py") == (10, "low")
    # polling tier (no path given)
    assert await find(_Cache({10: "claude_code"}), None) == (10, "medium")


class _Recorder:
    def __init__(self):
        self.calls = []

    async def ingest_file_event(self, event):
        self.calls.append(event)


class _Attributor:
    class sessions:
        @staticmethod
        async def touch(agent_id, resumed=False):
            return "sess"

    def get_agent_for_pid(self, pid):
        return "claude_code"

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        return 1


@pytest.mark.asyncio
async def test_native_events_carry_medium_or_low_and_the_change_type_etw_keeps_high(monkeypatch, db):
    real_find = file_watcher._find_owning_agent_pid

    async def one_agent(pid_cache, path=None):
        return await real_find(_Cache({10: "claude_code"}), None)

    monkeypatch.setattr(file_watcher, "_find_owning_agent_pid", one_agent)
    recorder = _Recorder()
    handler = file_watcher.VlawFileHandler(_Attributor(), recorder, asyncio.get_running_loop(), pid_cache=None, use_pid_heuristic=True)

    await handler._handle_polled_event("C:/proj/src/new.py", "file_write", "create")
    await handler._handle_polled_event("C:/proj/src/old.py", "file_delete", "delete")
    await handler.handle_etw_event(4242, "C:/proj/src/etw.py", "file_write", 1.0, "move")

    native = [c for c in recorder.calls if c["event_source"] == "realtime_heuristic"]
    assert [(c["change"], c["attribution_confidence"]) for c in native] == [("create", "medium"), ("delete", "medium")]
    (etw,) = [c for c in recorder.calls if c["event_source"] == "etw"]
    assert etw["attribution_confidence"] == "high" and etw["change"] == "move"


def test_watchdog_event_names_map_to_change_types():
    assert file_watcher.CHANGE_MAP == {"created": "create", "modified": "write", "moved": "move", "deleted": "delete"}


def test_etw_event_ids_map_to_change_types():
    from watchers import etw_file_watcher as etw

    assert etw.EVENT_ID_TO_CHANGE[etw.TASK_NAME_CREATE] == "create"
    assert etw.EVENT_ID_TO_CHANGE[etw.TASK_WRITE] == "write"
    assert etw.EVENT_ID_TO_CHANGE[etw.TASK_RENAME] == "move"
    assert etw.EVENT_ID_TO_CHANGE[etw.TASK_DELETE_PATH] == "delete"
    assert set(etw.EVENT_ID_TO_CHANGE) == set(etw.EVENT_ID_TO_TYPE)


# ----------------------------------------------------------------- wording

def test_attribution_wording():
    guess = attribution_for("claude_code", "realtime_heuristic", "medium")
    assert guess["attribution"] == "best_guess"
    assert guess["attribution_label"] == "attributed to claude_code (best guess), confidence medium"
    assert attribution_for("claude_code", "poll", "low")["attribution"] == "best_guess"

    exact = attribution_for("claude_code", "etw", "high")
    assert exact["attribution"] == "exact" and exact["attribution_label"] == "by claude_code"
    assert "best guess" not in exact["attribution_label"]


async def _agent(db, label="claude_code_attr"):
    name = f"{label}_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name))
    await db.commit()
    return cur.lastrowid, name


async def _event(db, agent_id, sid, path, *, event_type="file_write", source="realtime_heuristic",
                 confidence="medium", change=None, created="2026-10-11 06:08:15", paths=None):
    detail = {"attribution_confidence": confidence}
    if change:
        detail["change"] = change
    if paths:
        detail["paths"] = paths
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail, event_source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (agent_id, sid, event_type, path, json.dumps(detail), source, created),
    )


async def _session(db, agent_id):
    sid = f"sess_{uuid.uuid4().hex[:8]}"
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (sid, agent_id),
    )
    await db.commit()
    return sid


async def _cleanup(db, agent_id):
    await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
    await db.commit()


@pytest.mark.asyncio
async def test_events_api_labels_file_events_but_not_other_events(db):
    agent_id, name = await _agent(db)
    sid = await _session(db, agent_id)
    await _event(db, agent_id, sid, "C:/p/guess.py", change="write")
    await _event(db, agent_id, sid, "C:/p/exact.py", source="etw", confidence="high", change="create")
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'proc_spawn', 'git.exe', '{}')",
        (agent_id, sid),
    )
    await db.commit()
    try:
        data = await events_module.get_events(agent=agent_id, type=None, since=None, session=sid, q=None, offset=0, limit=50)
        by_path = {e["path"]: e for e in data["events"]}
        assert by_path["C:/p/guess.py"]["attribution"] == "best_guess"
        assert by_path["C:/p/guess.py"]["attribution_confidence"] == "medium"
        assert by_path["C:/p/guess.py"]["attribution_label"].startswith(f"attributed to {name} (best guess)")
        assert by_path["C:/p/exact.py"]["attribution"] == "exact" and by_path["C:/p/exact.py"]["change"] == "create"
        assert "attribution" not in by_path["git.exe"]
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_attribution_note_in_reports_only_without_etw(db):
    assert export_module.ATTRIBUTION_NOTE == (
        "Without ETW, file changes are attributed to the agent running at the time. "
        "A change made by you may be shown under an agent."
    )
    assert export_module.ATTRIBUTION_NOTE in export_module.current_report_notes()
    summary = await export_module._build_summary("today")
    assert export_module.ATTRIBUTION_NOTE in summary["report_notes"]

    set_file_watcher_tier("etw")
    assert export_module.ATTRIBUTION_NOTE not in export_module.current_report_notes()


def test_docs_and_ui_state_the_attribution_limits():
    doc = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert "Without ETW, file changes are attributed to the agent running at the time. A change made by you may be shown under an agent." in doc
    assert "If no agent process is running when a file changes, the change is not recorded" in doc
    for name in ("LiveFeed.jsx", "History.jsx"):
        text = (ROOT / "frontend" / "src" / "components" / name).read_text(encoding="utf-8")
        assert "(best guess)" in text, name


# --------------------------------------------------- per-session report

@pytest.mark.asyncio
async def test_session_report_lists_every_kind_of_change_with_time_and_attribution(db):
    agent_id, name = await _agent(db)
    sid = await _session(db, agent_id)
    await scope_store.save_scope(db, ["C:/proj"], {})
    await _event(db, agent_id, sid, "C:/proj/new.py", change="create", created="2026-10-11 06:00:01")
    await _event(db, agent_id, sid, "C:/proj/edit.py", change="write", created="2026-10-11 06:00:02")
    await _event(db, agent_id, sid, "C:/proj/gone.py", event_type="file_delete", change="delete", created="2026-10-11 06:00:03")
    await _event(db, agent_id, sid, "C:/proj/moved.py", change="move", source="etw", confidence="high", created="2026-10-11 06:00:04")
    await _event(db, agent_id, sid, "C:/proj/legacy.py", change=None, created="2026-10-11 06:00:05")           # recorded before change types existed
    await _event(db, agent_id, sid, "C:/proj/sub", source="poll", confidence="medium", created="2026-10-11 06:00:06",
                 paths=["C:/proj/sub/a.py", "C:/proj/sub/b.py"])                                                 # polling-tier aggregate
    await _event(db, agent_id, sid, "C:/Users/me/.aws/credentials", event_type="cred_access", change="write", created="2026-10-11 06:00:07")
    await db.commit()
    try:
        report = await sessions_module._build_session_report_data(db, sid)
        rows = {r["path"]: r for r in report["file_changes"]}

        assert rows["C:/proj/new.py"]["change"] == "create"
        assert rows["C:/proj/gone.py"]["change"] == "delete", "deletes are included"
        assert rows["C:/proj/moved.py"]["change"] == "move"
        assert rows["C:/proj/legacy.py"]["change"] == "write", "no recorded change type falls back to the event type"
        assert {"C:/proj/sub/a.py", "C:/proj/sub/b.py"} <= set(rows)
        assert rows["C:/proj/new.py"]["time"] == "2026-10-11T06:00:01+00:00"

        guess, exact = rows["C:/proj/new.py"], rows["C:/proj/moved.py"]
        assert guess["attribution"] == "best_guess" and guess["attribution_confidence"] == "medium"
        assert guess["attribution_label"] == f"attributed to {name} (best guess), confidence medium"
        assert exact["attribution"] == "exact" and exact["attribution_label"] == f"by {name}"

        assert report["file_changes_by_type"] == {"create": 1, "write": 5, "delete": 1, "move": 1}
        assert report["file_changes_total"] == 7 + 1 and report["file_changes_not_shown"] == 0
        assert report["files_touched_count"] == 8
        assert rows["C:/Users/me/.aws/credentials"]["is_credential"] is True
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_session_report_caps_rows_and_counts_the_rest(db):
    agent_id, _name = await _agent(db)
    sid = await _session(db, agent_id)
    for i in range(250):
        await _event(db, agent_id, sid, f"C:/proj/f{i:03d}.py", change="delete" if i % 5 == 0 else "write",
                     event_type="file_delete" if i % 5 == 0 else "file_write")
    await db.commit()
    try:
        report = await sessions_module._build_session_report_data(db, sid)
        assert len(report["file_changes"]) == sessions_module.MAX_FILE_CHANGE_ROWS == 200
        assert report["file_changes_not_shown"] == 50 and report["file_changes_total"] == 250
        assert report["file_changes_by_type"] == {"delete": 50, "write": 200}, "counts cover all rows, not only the 200 shown"
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_scope_label_uses_watched_folders_not_the_launch_directory(db, monkeypatch):
    """The installed app's launch directory is Vigil's own install folder. The
    old comparison against it labelled every project file OUTSIDE SCOPE."""
    import core.red_lines as red_lines

    monkeypatch.setattr(red_lines, "SESSION_LAUNCH_DIR", Path("C:/Program Files/Vigil/tray"))
    agent_id, _name = await _agent(db)
    sid = await _session(db, agent_id)
    await _event(db, agent_id, sid, "C:/Users/me/project/src/app.py", change="write")
    await _event(db, agent_id, sid, "C:/Users/me/elsewhere/notes.txt", change="write")
    await db.commit()
    try:
        await scope_store.save_scope(db, ["C:/Users/me/project"], {})
        report = await sessions_module._build_session_report_data(db, sid)
        scopes = {r["path"]: r["scope"] for r in report["file_changes"]}
        assert scopes == {"C:/Users/me/project/src/app.py": "in_scope", "C:/Users/me/elsewhere/notes.txt": "outside_scope"}

        await scope_store.save_scope(db, [], {})        # nothing watched: no label at all
        report = await sessions_module._build_session_report_data(db, sid)
        assert {r["scope"] for r in report["file_changes"]} == {None}
        assert all(f["outside_workdir"] is False for f in report["files_touched"])
    finally:
        await _cleanup(db, agent_id)


def test_scope_label_helper_and_sessions_module_do_not_use_the_launch_directory():
    assert scope_label("C:\\Users\\me\\project\\src\\a.py", ["C:/Users/me/project"]) == "in_scope"
    assert scope_label("C:/Users/me/project2/a.py", ["C:/Users/me/project"]) == "outside_scope"
    assert scope_label("C:/anything", []) is None
    assert "SESSION_LAUNCH_DIR" not in (Path(sessions_module.__file__)).read_text(encoding="utf-8")


def _capture_pdf_text(coro_factory):
    from reportlab.pdfgen import canvas

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    return drawn, patch.object(canvas.Canvas, "drawString", capture)


@pytest.mark.asyncio
async def test_session_pdf_and_preview_json_show_the_changes(db):
    agent_id, name = await _agent(db)
    sid = await _session(db, agent_id)
    await scope_store.save_scope(db, ["C:/proj"], {})
    await _event(db, agent_id, sid, "C:/proj/a.py", change="create", created="2026-10-11 06:00:01")
    await _event(db, agent_id, sid, "D:/other/b.py", event_type="file_delete", change="delete", created="2026-10-11 06:00:02")
    await db.commit()
    try:
        drawn, cap = _capture_pdf_text(None)
        with cap:
            await sessions_module.get_session_report_pdf(sid)
        text = "\n".join(drawn)
        assert "File changes (2)" in text and "By change: create 1, delete 1" in text
        assert "[OK] 2026-10-11T06:00:01+00:00  create  C:/proj/a.py" in text
        assert "[OUTSIDE SCOPE] 2026-10-11T06:00:02+00:00  delete  D:/other/b.py" in text
        assert f"attributed to {name} (best guess), confidence medium" in text

        preview = await sessions_module.get_session_report_preview(sid)
        files = [e for e in preview["events"] if e["kind"] == "file"]
        assert {(f["path"], f["change"], f["time"]) for f in files} == {
            ("C:/proj/a.py", "create", "2026-10-11T06:00:01+00:00"),
            ("D:/other/b.py", "delete", "2026-10-11T06:00:02+00:00"),
        }
        assert preview["file_changes_by_type"] == {"create": 1, "delete": 1} and preview["watched_folders"] == ["C:/proj"]

        await scope_store.save_scope(db, [], {})
        drawn, cap = _capture_pdf_text(None)
        with cap:
            await sessions_module.get_session_report_pdf(sid)
        text = "\n".join(drawn)
        assert not any(line.startswith(("[OUTSIDE SCOPE] 2026", "[OK] 2026")) for line in drawn), "no scope label on any row"
        assert "No project folder is watched, so no scope label is shown." in text
    finally:
        await _cleanup(db, agent_id)


# ------------------------------------------------------ daily exports

@pytest.mark.asyncio
async def test_daily_summary_has_a_bounded_files_changed_block(db):
    agent_id, _name = await _agent(db)
    sid = await _session(db, agent_id)
    for d in range(15):
        for i in range(8):
            await _event(db, agent_id, sid, f"C:/proj/dir{d:02d}/f{i}.py", change="write",
                         created=_now_sql())
    await db.commit()
    try:
        summary = await export_module._build_summary("today")
        session = next(s for s in summary["sessions"] if s["id"] == sid)
        changed = session["files_changed"]
        assert changed["total"] == 120 and changed["by_change"] == {"write": 120}
        assert len(changed["top_directories"]) == 10
        assert len(changed["first_paths"]) == 50
        assert changed["note"] == "full list in the session report"
        assert set(changed) >= {"total", "by_change", "top_directories", "first_paths", "note", "recorded_rows"}
    finally:
        await _cleanup(db, agent_id)


def test_summarise_is_bounded_and_deduplicates_paths():
    changes = [{"path": f"C:/p/d{i % 30}/f{i}.py", "change": "write"} for i in range(500)]
    changes += [{"path": "C:/p/d0/f0.py", "change": "delete"}] * 3
    result = summarise(changes)
    assert result["total"] == 503 and len(result["top_directories"]) == 10 and len(result["first_paths"]) == 50
    assert len(set(result["first_paths"])) == 50


def test_pdf_lists_session_files_changed_within_a_global_budget():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    def session(i):
        return {
            "id": f"{i:08d}-aaaa", "started_at": "2026-03-15 08:00:00", "ended_at": "2026-03-15 09:00:00",
            "operator_username": "a", "operator_hostname": "h", "agent_name": "claude_code",
            "event_count_in_period": 5, "no_activity": False, "resumed": False,
            "files_changed": {
                "total": 50, "by_change": {"write": 45, "delete": 5}, "recorded_rows": 50, "note": "full list in the session report",
                "top_directories": [{"directory": f"C:/p/d{i}", "count": 50}],
                "first_paths": [f"C:/p/d{i}/f{n}.py" for n in range(50)],
            },
        }

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15", "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00", "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC", "event_count": 10, "sessions": [session(i) for i in range(10)], "alerts": [],
            "report_notes": export_module.REPORT_NOTES, "coverage_available": False, "tracking_started_at": None,
            "active_seconds": 0, "period_seconds_measured": 0, "gaps": [], "short_gap_count": 0, "short_gap_seconds": 0,
        }

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    app = FastAPI()
    app.include_router(export_module.router)
    with patch.object(export_module, "_build_summary", fake_build_summary), \
         patch.object(canvas.Canvas, "drawString", capture):
        assert TestClient(app).get("/export/pdf").status_code == 200
    summary_lines = [t for t in drawn if t.startswith("files changed: 50 (delete 5, write 45); full list in the session report")]
    assert len(summary_lines) == 10
    path_lines = [t for t in drawn if t.startswith("C:/p/d") and ".py" in t]
    assert len(path_lines) == export_module.PDF_MAX_FILE_PATH_LINES == 200, "the PDF lists at most 200 paths in total"
    import re
    assert len([t for t in drawn if re.match(r"^50\s+C:/p/d", t.strip())]) == 10, "top directories are listed for every session"


@pytest.mark.asyncio
async def test_daily_json_timestamps_all_carry_an_explicit_offset(db):
    agent_id, _name = await _agent(db)
    sid = await _session(db, agent_id)
    await db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, session_id, rule_type) VALUES (?, 'low', 't', 'd', ?, 'policy')",
        (agent_id, sid),
    )
    await db.commit()
    try:
        data = await export_module.export_json(date="today")
        session = next(s for s in data["sessions"] if s["id"] == sid)
        assert session["started_at"].endswith("+00:00") and "T" in session["started_at"]
        assert data["generated_at"].endswith("+00:00")
        alert = next(a for a in data["alerts"] if a["session_id"] == sid)
        assert alert["created_at"].endswith("+00:00")

        import re
        bare = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$")

        def walk(value, path="$"):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield from walk(v, f"{path}.{k}")
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    yield from walk(v, f"{path}[{i}]")
            elif isinstance(value, str) and bare.match(value):
                yield path

        assert list(walk(data)) == [], "every bare timestamp must have an offset"
    finally:
        await db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await _cleanup(db, agent_id)


def test_with_utc_offsets_leaves_other_strings_alone():
    result = export_module.with_utc_offsets({
        "a": "2026-10-11 06:08:14", "b": "2026-10-11T06:08:14+00:00", "c": "2026-10-11", "d": "text 2026-10-11 06:08:14",
        "n": [{"x": "2026-10-11 01:02:03"}],
    })
    assert result == {
        "a": "2026-10-11T06:08:14+00:00", "b": "2026-10-11T06:08:14+00:00", "c": "2026-10-11",
        "d": "text 2026-10-11 06:08:14", "n": [{"x": "2026-10-11T01:02:03+00:00"}],
    }


def test_change_type_and_utc_helpers():
    assert change_type("file_write", {"change": "move"}) == "move"
    assert change_type("file_delete", {}) == "delete"
    assert change_type("file_write", {}) == "write"
    assert change_type("cred_access", {"event_type": "file_delete"}) == "delete"
    assert utc_iso("2026-10-11 06:08:14") == "2026-10-11T06:08:14+00:00"
    assert utc_iso(None) is None


# --------------------------------------------------------- history search

@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_history_search_matches_a_session_id_prefix():
    script = """
    import { parseQuery } from './frontend/src/queryParser.js'
    const events = [
      { session_id: 'a1b2c3d4-0000-4000-8000-000000000001', path: '/x/one.py', event_type: 'file_write', agent_name: 'claude_code', created_at: '2026-10-11 06:00:00' },
      { session_id: 'ffeeddcc-0000-4000-8000-000000000002', path: '/x/two.py', event_type: 'file_write', agent_name: 'codex', created_at: '2026-10-11 06:00:01' },
    ]
    const out = {
      prefix8: parseQuery('a1b2c3d4', events).map((e) => e.path),
      prefix4: parseQuery('ffee', events).map((e) => e.path),
      text: parseQuery('codex', events).map((e) => e.path),
      none: parseQuery('abcd', events).length,
    }
    console.log(JSON.stringify(out))
    """
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    assert out["prefix8"] == ["/x/one.py"] and out["prefix4"] == ["/x/two.py"]
    assert out["text"] == ["/x/two.py"] and out["none"] == 0


BS = chr(92)


def _now_sql():
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------- daily file lists: checkpoints, order, slashes

@pytest.mark.asyncio
async def test_daily_files_changed_hides_checkpoint_paths_and_lists_watched_first(db, monkeypatch):
    async def fake_scope(_db):
        return ["C:/work/proj"]

    monkeypatch.setattr(export_module, "get_scope_directories", fake_scope)
    agent_id, name = await _agent(db)
    sid = await _session(db, agent_id)
    for i in range(55):
        await _event(db, agent_id, sid, f"C:/Users/u/.claude/file-history/abc/v{i}".replace("/", BS), change="write",
                     created=_now_sql())
    await _event(db, agent_id, sid, "C:/elsewhere/other.txt".replace("/", BS), change="write", created=_now_sql())
    for i in range(5):
        await _event(db, agent_id, sid, f"C:/work/proj/src/f{i}.py".replace("/", BS), change="create", created=_now_sql())
    await db.commit()
    try:
        summary = await export_module._build_summary("today")
        changed = next(s for s in summary["sessions"] if s["id"] == sid)["files_changed"]
        assert changed["first_paths"][:5] == [f"C:/work/proj/src/f{i}.py" for i in range(5)]
        assert changed["first_paths"][5] == "C:/elsewhere/other.txt" and len(changed["first_paths"]) == 6
        assert all("file-history" not in p for p in changed["first_paths"])
        assert changed["checkpoint_note"] == "55 checkpoint writes in the agent's hidden cache, not listed"
        assert changed["total"] == 61 and changed["by_change"] == {"write": 56, "create": 5}
        counted = {d["directory"]: d["count"] for d in changed["top_directories"]}
        assert counted["C:/Users/u/.claude/file-history/abc"] == 55
        assert all("\\" not in p for p in changed["first_paths"]) and all("\\" not in d for d in counted)
        assert changed["attribution_note"] == f"attributed to {name} (best guess)"
        assert "best_guess_attribution" not in changed
    finally:
        await _cleanup(db, agent_id)


def test_summarise_caps_after_removing_checkpoint_paths():
    changes = [{"path": f"C:/Users/u/.claude/file-history/x/{i}".replace("/", BS), "change": "write"} for i in range(80)]
    changes += [{"path": f"C:/p/f{i}".replace("/", BS), "change": "write"} for i in range(60)]
    result = summarise(changes, scope_dirs=["C:/p"])
    assert len(result["first_paths"]) == 50 and all(p.startswith("C:/p/") for p in result["first_paths"])
    assert result["checkpoint_writes"] == 80 and result["total"] == 140


def test_pdf_prints_checkpoint_and_attribution_notes_and_no_checkpoint_paths():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    session = {
        "id": "11111111-aaaa", "started_at": "2026-03-15 08:00:00", "ended_at": "2026-03-15 09:00:00",
        "operator_username": "a", "operator_hostname": "h", "agent_name": "claude_code",
        "event_count_in_period": 5, "no_activity": False, "resumed": False, "checkpoint_writes": 4,
        "files_changed": {
            "total": 5, "by_change": {"write": 5}, "recorded_rows": 5, "note": "full list in the session report",
            "top_directories": [{"directory": "C:/p", "count": 1}], "first_paths": ["C:/p/a.py"],
            "checkpoint_writes": 4, "attribution_note": "attributed to claude_code (best guess)",
            "checkpoint_note": "4 checkpoint writes in the agent's hidden cache, not listed",
        },
    }

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15", "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00", "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC", "event_count": 5, "sessions": [session], "alerts": [],
            "report_notes": export_module.REPORT_NOTES, "coverage_available": False, "tracking_started_at": None,
            "active_seconds": 0, "period_seconds_measured": 0, "gaps": [], "short_gap_count": 0, "short_gap_seconds": 0,
        }

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    app = FastAPI()
    app.include_router(export_module.router)
    with patch.object(export_module, "_build_summary", fake_build_summary), patch.object(canvas.Canvas, "drawString", capture):
        assert TestClient(app).get("/export/pdf").status_code == 200
    assert "attributed to claude_code (best guess)" in drawn
    assert drawn.count("4 checkpoint writes in the agent's hidden cache, not listed") == 1
    assert not any("file-history" in t for t in drawn)
