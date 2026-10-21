"""Sessions opened only because Vigil found an agent process already running at startup (resumed=1) and
nothing else: they are not current sessions, their already_running spawn markers are not spawns, and the
session report says so. Fixtures are shaped like sessions 495a25f5 (open) and cc131709 (start == end) from
the field report: resumed, two already_running proc_spawn events (codex.exe and its conhost.exe), no file events."""

import json
import uuid
from unittest.mock import patch

import pytest
import pytest_asyncio

import api.sessions as sessions_module
import db.database as database
from core import mcp_service
from core.sessions import has_activity_exists_sql, has_real_activity, session_visible_sql

OLD_FOOTER = ("Independent OS-level observer", "Evidence is captured independently of agent self-reporting")


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    """A fresh database of its own, so "the current session" is exactly what the test created."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "vlaw.db")
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


async def make_agent(db) -> int:
    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'codex.exe', 1)", (f"codex_{uuid.uuid4().hex[:6]}",))
    await db.commit()
    return cur.lastrowid


async def add_spawn(db, agent_id, sid, name, pid, parent, *, already_running, activity_spawn):
    # the recorder stores the bare executable name in detail.command, while the path column may hold a whole command line
    import re

    found = re.search(r"([A-Za-z0-9_.\-]+\.exe)", name, re.I)
    detail = {"pid": pid, "parent_pid": parent, "command": found.group(1) if found else name, "args": [], "suspicious": False,
              "process_started": 1792429524, "activity_spawn": activity_spawn}
    if already_running:
        detail["already_running"] = True
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail, file_count, severity, pid, created_at) "
        "VALUES (?, ?, 'proc_spawn', ?, ?, 1, 'low', ?, '2026-10-19 17:05:41')",
        (agent_id, sid, name, json.dumps(detail), pid),
    )


async def resumed_session(db, agent_id, *, closed: bool, started="2026-10-19 17:05:41") -> str:
    """495a25f5 (closed=False) or cc131709 (closed=True, ended_at == started_at): two already_running markers."""
    sid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, ?, ?, 1)",
        (sid, agent_id, started, started if closed else None),
    )
    await add_spawn(db, agent_id, sid, "codex.exe", 42468, 33624, already_running=True, activity_spawn=False)
    await add_spawn(db, agent_id, sid, "conhost.exe", 51736, 42468, already_running=True, activity_spawn=True)
    await db.commit()
    return sid


def utc_ago(minutes: float) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


async def add_file_write(db, agent_id, sid, path="C:/proj/src/app.py", at="2026-10-19 17:10:00"):
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count, severity, created_at) "
        "VALUES (?, ?, 'file_write', ?, 1, 'low', ?)",
        (agent_id, sid, path, at),
    )
    await db.commit()


def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(sessions_module.router)
    return TestClient(app)


def pdf_text(c, path):
    from reportlab.pdfgen import canvas

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        response = c.get(path)
    assert response.status_code == 200
    return "\n".join(drawn)


# ------------------------------------------------------------------ the one definition

@pytest.mark.asyncio
async def test_real_activity_is_a_file_event_or_a_spawn_that_is_not_an_already_running_marker(db):
    agent = await make_agent(db)
    open_resumed = await resumed_session(db, agent, closed=False)
    closed_resumed = await resumed_session(db, agent, closed=True)
    with_file = await resumed_session(db, agent, closed=False)
    await add_file_write(db, agent, with_file)
    with_spawn = await resumed_session(db, agent, closed=False)
    await add_spawn(db, agent, with_spawn, "git.exe", 6001, 42468, already_running=False, activity_spawn=True)
    await db.commit()

    assert await has_real_activity(db, open_resumed) is False
    assert await has_real_activity(db, closed_resumed) is False
    assert await has_real_activity(db, with_file) is True
    assert await has_real_activity(db, with_spawn) is True

    cur = await db.execute(f"SELECT s.id FROM sessions s WHERE {session_visible_sql('s')} ORDER BY s.id")
    visible = {r["id"] for r in await cur.fetchall()}
    assert visible == {with_file, with_spawn}
    cur = await db.execute(f"SELECT s.id FROM sessions s WHERE {has_activity_exists_sql('s')}")
    assert {r["id"] for r in await cur.fetchall()} == {with_file, with_spawn}


# ------------------------------------------------------------------ current session

@pytest.mark.asyncio
async def test_a_resumed_session_with_only_markers_is_not_the_current_session(db):
    agent = await make_agent(db)
    await resumed_session(db, agent, closed=False)   # like 495a25f5
    await resumed_session(db, agent, closed=True)    # like cc131709
    result = await mcp_service._get_current_session({})
    assert result["status"] == "none" and result["session_id"] is None
    assert result["resumed"] is False and result["has_activity"] is False


@pytest.mark.asyncio
async def test_a_resumed_session_that_later_has_a_real_file_write_is_shown_with_it(db):
    agent = await make_agent(db)
    marker_only = await resumed_session(db, agent, closed=False, started="2026-10-19 17:00:00")
    real = await resumed_session(db, agent, closed=False, started=utc_ago(3))
    await add_file_write(db, agent, real, at=utc_ago(1))

    result = await mcp_service._get_current_session({})
    assert result["session_id"] == real and result["status"] == "active"
    assert result["resumed"] is True and result["has_activity"] is True
    assert result["files_touched"] == 1
    assert result["session_id"] != marker_only


@pytest.mark.asyncio
async def test_session_list_flags_activity_and_the_open_filter_leaves_out_marker_only_sessions(db):
    agent = await make_agent(db)
    marker_only = await resumed_session(db, agent, closed=False)
    marker_closed = await resumed_session(db, agent, closed=True)
    real = await resumed_session(db, agent, closed=False)
    await add_file_write(db, agent, real)

    c = client()
    everything = {s["id"]: s for s in c.get("/sessions").json()["sessions"]}
    assert set(everything) == {marker_only, marker_closed, real}, "the rows stay available"
    assert everything[marker_only]["has_activity"] is False and everything[marker_closed]["has_activity"] is False
    assert everything[real]["has_activity"] is True and everything[real]["resumed"] == 1
    open_ids = {s["id"] for s in c.get("/sessions", params={"status": "open"}).json()["sessions"]}
    assert open_ids == {real}

    # the rows are still there for the reports by id
    assert c.get(f"/sessions/{marker_only}/report/preview").status_code == 200


# ------------------------------------------------------------------ the report

@pytest.mark.asyncio
async def test_report_for_a_marker_only_session_counts_no_spawns_says_so_and_lists_both_processes(db):
    agent = await make_agent(db)
    for closed in (False, True):  # 495a25f5 and cc131709
        sid = await resumed_session(db, agent, closed=closed)
        c = client()
        preview = c.get(f"/sessions/{sid}/report/preview").json()
        assert preview["process_spawns"] == 0
        assert preview["already_running_count"] == 2
        assert preview["resumed"] is True
        assert preview["resumed_note"] == ("Vigil began watching while this agent was already running. "
                                          "Start time and duration are from when watching began.")
        rows = preview["processes"]
        assert [(r["name"], r["pid"], r["parent_pid"], r["already_running"]) for r in rows] == [
            ("codex.exe", 42468, 33624, True), ("conhost.exe", 51736, 42468, True)]

        text = pdf_text(c, f"/sessions/{sid}/report")
        flat = " ".join(text.split())  # the note wraps over two lines in the PDF
        assert "Vigil began watching while this agent was already running. Start time and duration are from when watching began." in flat
        assert "Already running when watching began: 2" in text
        assert "Processes (2)" in text and "codex.exe" in text and "conhost.exe" in text
        assert text.count("already running") >= 2
        assert "Generated by Vigil from OS-level records." in text
        assert "See 'What this report covers' above for what is not recorded." in text
        for old in OLD_FOOTER:
            assert old not in text


@pytest.mark.asyncio
async def test_report_for_a_resumed_session_with_real_activity_keeps_the_label_and_shows_the_activity(db):
    agent = await make_agent(db)
    sid = await resumed_session(db, agent, closed=False)
    await add_file_write(db, agent, sid, "C:/proj/src/changed.py")
    await add_spawn(db, agent, sid, "git.exe", 6001, 42468, already_running=False, activity_spawn=True)
    await db.commit()

    c = client()
    preview = c.get(f"/sessions/{sid}/report/preview").json()
    assert preview["process_spawns"] == 1, "only the git.exe spawn; the two markers are not spawns"
    assert preview["already_running_count"] == 2 and preview["processes_total"] == 3
    assert preview["files_touched"] == 1 and preview["resumed"] is True
    text = pdf_text(c, f"/sessions/{sid}/report")
    assert "changed.py" in text and "git.exe" in text and "Already running when watching began: 2" in text


@pytest.mark.asyncio
async def test_an_ordinary_session_has_no_resumed_note_and_the_process_list_is_capped_at_20(db):
    agent = await make_agent(db)
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, '2026-10-19 09:00:00', '2026-10-19 09:10:00', 0)", (sid, agent))
    for i in range(25):
        await add_spawn(db, agent, sid, f"tool{i}.exe", 7000 + i, 42468, already_running=False, activity_spawn=True)
    await db.commit()

    c = client()
    preview = c.get(f"/sessions/{sid}/report/preview").json()
    assert preview["resumed"] is False and preview["resumed_note"] is None and preview["already_running_count"] == 0
    assert preview["process_spawns"] == 25 and len(preview["processes"]) == 20 and preview["processes_total"] == 25
    text = pdf_text(c, f"/sessions/{sid}/report")
    assert "Vigil began watching while this agent was already running." not in text
    assert "Already running when watching began" not in text
    assert "5 more not shown." in text


# ------------------------------------------------------------------ idle: a display rule, nothing is written

async def open_session(db, agent_id, *, started_min_ago, event_min_ago=None, resumed=False) -> str:
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, resumed) VALUES (?, ?, ?, ?)",
                     (sid, agent_id, utc_ago(started_min_ago), 1 if resumed else 0))
    await db.commit()
    if event_min_ago is not None:
        await add_file_write(db, agent_id, sid, at=utc_ago(event_min_ago))
    return sid


async def snapshot(db):
    cur = await db.execute("SELECT (SELECT COUNT(*) FROM sessions) s, (SELECT COUNT(*) FROM events) e, "
                           "(SELECT COUNT(*) FROM sessions WHERE ended_at IS NOT NULL) closed")
    return dict(await cur.fetchone())


@pytest.mark.asyncio
async def test_an_open_session_with_its_last_event_10_minutes_ago_is_idle_and_one_minute_ago_is_active(db):
    agent = await make_agent(db)
    quiet = await open_session(db, agent, started_min_ago=30, event_min_ago=10)
    before = await snapshot(db)
    result = await mcp_service._get_current_session({})
    assert result["session_id"] == quiet and result["status"] == "idle"
    assert result["last_activity_at"] == utc_ago(10) or result["last_activity_at"] <= utc_ago(9.9)
    assert await snapshot(db) == before, "display only: nothing is written"

    busy = await open_session(db, agent, started_min_ago=5, event_min_ago=1)
    result = await mcp_service._get_current_session({})
    assert result["session_id"] == busy and result["status"] == "active"
    assert result["last_activity_at"] >= utc_ago(1.1)


@pytest.mark.asyncio
async def test_an_open_session_with_no_events_at_all_is_not_a_current_session(db):
    """Since the real-activity rule covers every session (not only resumed ones), a session with no events is hidden."""
    agent = await make_agent(db)
    await open_session(db, agent, started_min_ago=20)
    result = await mcp_service._get_current_session({})
    assert result["status"] == "none" and result["session_id"] is None


@pytest.mark.asyncio
async def test_a_marker_only_resumed_session_is_still_hidden_not_idle(db):
    agent = await make_agent(db)
    await resumed_session(db, agent, closed=False, started=utc_ago(30))
    result = await mcp_service._get_current_session({})
    assert result["status"] == "none" and result["session_id"] is None


@pytest.mark.asyncio
async def test_session_list_carries_idle_and_last_activity_for_open_sessions_only(db):
    agent = await make_agent(db)
    quiet = await open_session(db, agent, started_min_ago=30, event_min_ago=10)
    busy = await open_session(db, agent, started_min_ago=5, event_min_ago=1)
    closed = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, ?)", (closed, agent, utc_ago(60), utc_ago(50)))
    await db.commit()

    rows = {s["id"]: s for s in client().get("/sessions").json()["sessions"]}
    assert rows[quiet]["idle"] is True and rows[quiet]["last_activity_at"] <= utc_ago(9.9)
    assert rows[busy]["idle"] is False and rows[busy]["last_activity_at"] >= utc_ago(1.1)
    assert rows[closed]["idle"] is False and rows[closed]["last_activity_at"] is None


@pytest.mark.asyncio
async def test_the_pdf_says_idle_since_and_counts_the_duration_to_the_last_activity(db):
    agent = await make_agent(db)
    sid = await open_session(db, agent, started_min_ago=30, event_min_ago=20)   # watched for 10 minutes, then quiet
    c = client()
    preview = c.get(f"/sessions/{sid}/report/preview").json()
    assert preview["idle"] is True and preview["duration_minutes"] == 10.0
    text = pdf_text(c, f"/sessions/{sid}/report")
    assert "Idle since " in text and "Duration: 10.0 min" in text

    active = await open_session(db, agent, started_min_ago=5, event_min_ago=1)
    preview = c.get(f"/sessions/{active}/report/preview").json()
    assert preview["idle"] is False and preview["last_activity_at"] is None
    assert "Idle since" not in pdf_text(c, f"/sessions/{active}/report")


# ------------------------------------------------------------------ an agent that only started: dd20c0e9
# The Codex VS Code extension starts codex.exe when VS Code opens. That is not "already running" when Vigil sees
# it, and its console host (conhost.exe) is a child of it. Neither is real activity.

async def started_only_session(db, agent_id, *, started_min_ago=2) -> str:
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, resumed) VALUES (?, ?, ?, 0)",
                     (sid, agent_id, utc_ago(started_min_ago)))
    await add_spawn(db, agent_id, sid, "codex.exe", 9180, 33448, already_running=False, activity_spawn=False)
    await add_spawn(db, agent_id, sid, r"\??\C:\Windows\system32\conhost.exe 0x4", 29340, 9180, already_running=False, activity_spawn=True)
    await db.commit()
    return sid


@pytest.mark.asyncio
async def test_an_agent_exe_with_only_its_console_host_is_not_real_activity_and_is_hidden(db):
    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    assert await has_real_activity(db, sid) is False

    result = await mcp_service._get_current_session({})
    assert result["status"] == "none" and result["session_id"] is None

    rows = {r["id"]: r for r in client().get("/sessions").json()["sessions"]}
    assert rows[sid]["has_activity"] is False, "the row is still returned, flagged"
    assert sid not in {r["id"] for r in client().get("/sessions", params={"status": "open"}).json()["sessions"]}


@pytest.mark.asyncio
async def test_other_console_and_os_helpers_are_ignored_but_tools_the_agent_runs_are_real_activity(db):
    agent = await make_agent(db)
    for helper in ("wslhost.exe", "werfault.exe", "conhost.exe"):
        sid = await started_only_session(db, agent)
        await add_spawn(db, agent, sid, helper, 7000, 9180, already_running=False, activity_spawn=True)
        await db.commit()
        assert await has_real_activity(db, sid) is False, helper

    for tool in ("git.exe", "python.exe", "bash.exe", "cmd.exe", "powershell.exe", "node.exe"):
        sid = await started_only_session(db, agent)
        await add_spawn(db, agent, sid, tool, 7100, 9180, already_running=False, activity_spawn=True)
        await db.commit()
        assert await has_real_activity(db, sid) is True, tool


@pytest.mark.asyncio
async def test_a_file_write_is_real_activity_and_makes_the_session_the_current_one(db):
    agent = await make_agent(db)
    quiet = await started_only_session(db, agent, started_min_ago=4)
    busy = await started_only_session(db, agent, started_min_ago=3)
    await add_file_write(db, agent, busy, at=utc_ago(1))
    assert await has_real_activity(db, quiet) is False and await has_real_activity(db, busy) is True
    result = await mcp_service._get_current_session({})
    assert result["session_id"] == busy and result["has_activity"] is True and result["status"] == "active"


@pytest.mark.asyncio
async def test_mcp_session_history_returns_activity_resumed_idle_and_last_activity_without_dropping_rows(db):
    agent = await make_agent(db)
    started_only = await started_only_session(db, agent, started_min_ago=40)
    marker_only = await resumed_session(db, agent, closed=False, started=utc_ago(35))
    idle = await open_session(db, agent, started_min_ago=30, event_min_ago=10)
    active = await open_session(db, agent, started_min_ago=5, event_min_ago=1)
    closed = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, ?)", (closed, agent, utc_ago(90), utc_ago(80)))
    await add_file_write(db, agent, closed, at=utc_ago(85))

    history = {h["session_id"]: h for h in await mcp_service._get_session_history({"n": 20})}
    assert set(history) == {started_only, marker_only, idle, active, closed}, "nothing is filtered out of this route"
    assert history[started_only]["has_activity"] is False and history[started_only]["resumed"] is False
    assert history[marker_only]["has_activity"] is False and history[marker_only]["resumed"] is True
    assert history[idle]["has_activity"] is True and history[idle]["idle"] is True and history[idle]["last_activity_at"] <= utc_ago(9.9)
    assert history[active]["has_activity"] is True and history[active]["idle"] is False
    assert history[closed]["has_activity"] is True and history[closed]["idle"] is False and history[closed]["last_activity_at"] is None
    for h in history.values():
        assert {"has_activity", "resumed", "idle", "last_activity_at", "files_touched_count", "red_lines"} <= set(h)


# ------------------------------------------------------------------ the session list keeps its per-session aggregates incrementally

@pytest.mark.asyncio
async def test_the_session_list_picks_up_new_events_between_polls_and_survives_removed_events(db):
    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    c = client()

    first = {r["id"]: r for r in c.get("/sessions").json()["sessions"]}[sid]
    assert first["has_activity"] is False and first["net_connect_count"] == 0

    # an event added after the first poll is folded in (only the new rows are read)
    await add_file_write(db, agent, sid, at=utc_ago(0))
    await db.execute("INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, 'net_connect', 'example.com', ?)",
                     (agent, sid, utc_ago(0)))
    await db.commit()
    second = {r["id"]: r for r in c.get("/sessions").json()["sessions"]}[sid]
    assert second["has_activity"] is True and second["net_connect_count"] == 1
    assert second["last_activity_at"] >= utc_ago(0.5)

    # nothing new: the same answer
    again = {r["id"]: r for r in c.get("/sessions").json()["sessions"]}[sid]
    assert again["has_activity"] is True and again["net_connect_count"] == 1

    # events removed behind its back (never done by Vigil itself): the aggregates are rebuilt, not trusted
    await db.execute("DELETE FROM events WHERE session_id = ? AND event_type IN ('file_write', 'net_connect')", (sid,))
    await db.commit()
    rebuilt = {r["id"]: r for r in c.get("/sessions").json()["sessions"]}[sid]
    assert rebuilt["has_activity"] is False and rebuilt["net_connect_count"] == 0


@pytest.mark.asyncio
async def test_the_aggregates_are_per_database_file(db, tmp_path, monkeypatch):
    from core import sessions as sessions_core

    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    assert (await sessions_core.session_event_aggregates(db)).get(sid, {}).get("has_activity") is False
    key_before = sessions_core._aggregates["key"]
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "another.db")   # pretend a different database file
    await sessions_core.session_event_aggregates(db)
    assert sessions_core._aggregates["key"] != key_before, "a different database is not served from the old aggregates"


@pytest.mark.asyncio
async def test_vigils_own_processes_are_not_agent_activity(db):
    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    for own in ("vigil.exe", "vigil-backend.exe", "Vigil.exe"):
        await add_spawn(db, agent, sid, own, 7200, 9180, already_running=False, activity_spawn=True)
    await db.commit()
    assert await has_real_activity(db, sid) is False


# ------------------------------------------------------------------ ignored processes are compared by executable base name

RAW_COMMANDS_THAT_ARE_PLUMBING = [
    r"\??\C:\Windows\system32\conhost.exe 0x4",          # the line seen in the field report
    r"C:\Windows\System32\conhost.exe 0xffffffff -ForceV1",
    r'"C:\Windows\System32\conhost.exe" 0x4',
    r"conhost.exe",
    r"CONHOST.EXE 0x4",
    r"conhost",
    r"\??\C:\Windows\System32\wslhost.exe --distro Ubuntu",
    r"C:\Windows\System32\WerFault.exe -u -p 1234",
    r'"C:\Program Files\Vigil\tray\Vigil.exe" --autostart',
    r"C:\Program Files\Vigil\backend\vigil-backend.exe",
    r"C:/Program Files/Vigil/backend/vigil-backend.exe --port 7842",
]
RAW_COMMANDS_THAT_ARE_REAL = [
    r"C:\Program Files\Git\cmd\git.exe status",
    r"C:\conhost\git.exe status",                         # a folder called conhost is not the conhost process
    r"C:\tools\conhost-helper.exe run",                   # only the exact base name is ignored
    r"C:\tools\myconhost.exe",
    r"C:\Windows\System32\cmd.exe /c dir",
    r"bash.exe -c ls",
    r"node.exe server.js",
]


def test_executable_base_name_strips_the_prefix_the_folders_the_arguments_and_the_extension():
    from core.sessions import executable_base_name

    assert executable_base_name(r"\??\C:\Windows\system32\conhost.exe 0x4") == "conhost"
    assert executable_base_name(r'"C:\Program Files\Vigil\tray\Vigil.exe" --autostart') == "vigil"
    assert executable_base_name(r"C:\Program Files\Vigil\backend\vigil-backend.exe --port 1") == "vigil-backend"
    assert executable_base_name("C:/x/y/Git.EXE status") == "git"
    assert executable_base_name("conhost") == "conhost"
    assert executable_base_name("") == "" and executable_base_name(None) == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", RAW_COMMANDS_THAT_ARE_PLUMBING)
async def test_a_raw_command_line_of_an_ignored_process_is_not_real_activity(db, raw):
    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    await add_raw_spawn(db, agent, sid, raw)
    assert await has_real_activity(db, sid) is False, raw


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", RAW_COMMANDS_THAT_ARE_REAL)
async def test_a_raw_command_line_of_a_real_tool_is_real_activity(db, raw):
    agent = await make_agent(db)
    sid = await started_only_session(db, agent)
    await add_raw_spawn(db, agent, sid, raw)
    assert await has_real_activity(db, sid) is True, raw


@pytest.mark.asyncio
async def test_the_session_list_applies_the_same_rule_to_a_raw_command_line(db):
    agent = await make_agent(db)
    quiet = await started_only_session(db, agent)
    await add_raw_spawn(db, agent, quiet, r"\??\C:\Windows\system32\conhost.exe 0x4")
    busy = await started_only_session(db, agent)
    await add_raw_spawn(db, agent, busy, r"C:\Program Files\Git\cmd\git.exe status")
    rows = {r["id"]: r for r in client().get("/sessions").json()["sessions"]}
    assert rows[quiet]["has_activity"] is False and rows[busy]["has_activity"] is True


async def add_raw_spawn(db, agent_id, sid, command):
    """A proc_spawn whose detail.command is the whole command line, not the bare executable name."""
    detail = {"pid": 7300, "parent_pid": 9180, "command": command, "args": [], "suspicious": False,
              "process_started": 1792429524, "activity_spawn": True}
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail, file_count, severity, pid, created_at) "
        "VALUES (?, ?, 'proc_spawn', ?, ?, 1, 'low', 7300, '2026-10-19 17:05:41')",
        (agent_id, sid, command, json.dumps(detail)),
    )
    await db.commit()
