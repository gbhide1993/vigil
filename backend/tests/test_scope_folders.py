"""Watched project folders: single source of truth in the database
(core/scope_store.py), the add/remove API (api/scope.py) with live
scheduling, the safety filter for Vigil's own folders, and the report and
Settings wording. See conftest.py for why VLAW_DATA_DIR is set there rather
than here."""

import asyncio
import json
import os
import threading
import time
import types
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import HTTPException
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import api.export as export_module
import api.scope as scope_api
import core.own_paths as own_paths
import core.scope_store as scope_store
import db.database as database
from core.monitoring_status import set_file_watcher_tier
from core.scope_store import MAX_FOLDERS, ScopeError, get_scope_directories, validate_new_folder
from watchers.file_watcher import unwatch_folder, watch_folder

LOCAL = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
REMOTE = types.SimpleNamespace(client=types.SimpleNamespace(host="192.168.1.20"))


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    """The shared test DB is not reset between files: save the scope rows
    and restore them afterwards. The policy file is pointed at a missing
    file so the repo's own seed file never leaks into a test."""
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
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
    set_file_watcher_tier("folders")
    own_paths.reset_cache()
    await database.close_db()


async def _set_scope(db, paths):
    await scope_store.save_scope(db, paths, {})


# ------------------------------------------------- single source of truth

@pytest.mark.asyncio
async def test_database_value_is_authoritative_and_preserved(db, tmp_path, monkeypatch):
    """The developer machine: the database holds a folder the policy file
    does not list. It must be kept."""
    policy_file = tmp_path / "vlaw-policy.json"
    policy_file.write_text(json.dumps({"scope_directories": []}))
    monkeypatch.setattr("config.policy.POLICY_FILE", policy_file)

    await _set_scope(db, ["C:/Users/gbhid/vlaw"])
    assert await get_scope_directories(db) == ["C:/Users/gbhid/vlaw"]


@pytest.mark.asyncio
async def test_file_is_only_a_fallback_when_the_database_has_no_row(db, tmp_path, monkeypatch):
    policy_file = tmp_path / "vlaw-policy.json"
    policy_file.write_text(json.dumps({"scope_directories": ["D:/from/file"]}))
    monkeypatch.setattr("config.policy.POLICY_FILE", policy_file)

    assert await get_scope_directories(db) == ["D:/from/file"]            # no database row
    await _set_scope(db, [])
    assert await get_scope_directories(db) == []                           # an empty database list is a real value
    await _set_scope(db, ["C:/proj"])
    assert await get_scope_directories(db) == ["C:/proj"]


@pytest.mark.asyncio
async def test_alert_logic_reads_the_same_function(db, tmp_path, monkeypatch):
    from core.alerter import Alerter

    policy_file = tmp_path / "vlaw-policy.json"
    policy_file.write_text(json.dumps({"scope_directories": ["C:/file/only"]}))
    monkeypatch.setattr("config.policy.POLICY_FILE", policy_file)
    await _set_scope(db, ["C:/proj"])

    name = f"claude_code_scope_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name))
    await db.commit()
    agent_id = cur.lastrowid
    try:
        alerter = Alerter()
        await alerter.check_out_of_scope_access(agent_id, "C:/proj/src/app.py")
        await alerter.check_out_of_scope_access(agent_id, "C:/elsewhere/app.py")
        cur = await db.execute("SELECT description FROM alerts WHERE agent_id = ? AND reason = 'out_of_scope_access'", (agent_id,))
        rows = [r["description"] for r in await cur.fetchall()]
        assert len(rows) == 1 and "C:/elsewhere/app.py" in rows[0], "scope comes from the database, not the file"
    finally:
        await db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await db.commit()


# ---------------------------------------------------- own-folder safety filter

def test_own_install_and_data_folders_are_recognised(tmp_path, monkeypatch):
    data = tmp_path / "local" / "V-LAW" / "data"
    install = tmp_path / "pf" / "Vigil"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("VLAW_DATA_DIR", str(data))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "pf"))
    own_paths.reset_cache()
    try:
        assert own_paths.is_own_path(str(data / "vlaw.db"))
        assert own_paths.is_own_path(str(tmp_path / "local" / "V-LAW" / "vlaw-backend.log"))
        assert own_paths.is_own_path(str(install / "tray" / "Vigil.exe"))
        assert own_paths.is_own_path(str(install))
        assert not own_paths.is_own_path(str(tmp_path / "pf" / "VigilOther" / "x"))
        assert not own_paths.is_own_path(str(tmp_path / "projects" / "app" / "main.py"))
        assert not own_paths.is_own_path("")
    finally:
        own_paths.reset_cache()


class _Recorder:
    def __init__(self):
        self.calls = []

    async def ingest_file_event(self, event):
        self.calls.append(event)


class _Sessions:
    async def touch(self, agent_id, resumed=False):
        return "sess"


class _Attributor:
    sessions = _Sessions()

    def get_agent_for_pid(self, pid):
        return "claude_code"

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        return 1


@pytest.mark.asyncio
async def test_events_from_vigils_own_folders_are_never_recorded(db, tmp_path, monkeypatch):
    from watchers.file_watcher import VlawFileHandler

    data = tmp_path / "V-LAW" / "data"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("VLAW_DATA_DIR", str(data))
    own_paths.reset_cache()
    try:
        aggregator = _Recorder()
        handler = VlawFileHandler(_Attributor(), aggregator, asyncio.get_event_loop(), pid_cache=None)
        burst_calls = []

        async def record_event(path, event_type):
            burst_calls.append(path)

        handler._burst_detector.record_event = record_event

        await handler.handle_file_event(str(data / "vlaw.db-wal"), "file_write", "etw", 4242, "high")
        await handler.handle_file_event(str(tmp_path / "V-LAW" / "vlaw-backend.log"), "file_write", "poll", 4242, "high")
        assert aggregator.calls == [] and burst_calls == []

        project_file = str(tmp_path / "projects" / "app" / "main.py")
        await handler.handle_file_event(project_file, "file_write", "realtime_heuristic", 4242, "high")
        assert [c["path"] for c in aggregator.calls] == [project_file]
    finally:
        own_paths.reset_cache()


# ------------------------------------------------------------- validation

def _dir(tmp_path, name):
    p = tmp_path / name
    p.mkdir(parents=True, exist_ok=True)
    return str(p)


def _refused(path, existing=None, home=None):
    with pytest.raises(ScopeError) as exc:
        validate_new_folder(path, existing or [], home=home)
    return exc.value.code


def test_valid_folder_is_normalised_to_forward_slashes(tmp_path):
    project = _dir(tmp_path, "my project")
    stored = validate_new_folder(project, [], home=str(tmp_path / "home"))
    assert stored == Path(project).resolve().as_posix()
    assert "\\" not in stored


def test_refuses_empty_missing_and_file_paths(tmp_path):
    assert _refused("") == "empty_path"
    assert _refused("   ") == "empty_path"
    assert _refused(None) == "empty_path"
    assert _refused(str(tmp_path / "nope")) == "not_found"
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert _refused(str(f)) == "not_a_directory"


def test_refuses_unc_and_network_drives(tmp_path, monkeypatch):
    assert _refused("\\\\server\\share\\project") == "network_path"
    assert _refused("//server/share/project") == "network_path"
    monkeypatch.setattr(scope_store, "_is_network_drive", lambda _p: True)
    assert _refused(_dir(tmp_path, "mapped")) == "network_drive"


def test_refuses_drive_roots(tmp_path):
    root = os.path.splitdrive(os.path.abspath(str(tmp_path)))[0] + os.sep
    assert _refused(root) == "drive_root"


def test_refuses_the_home_folder_and_its_parents(tmp_path):
    home = _dir(tmp_path, "users/me")
    assert _refused(home, home=home) == "home_folder"
    assert _refused(str(Path(home).parent), home=home) == "contains_home"
    assert validate_new_folder(_dir(tmp_path, "users/me/project"), [], home=home).endswith("users/me/project")


@pytest.mark.skipif(os.name != "nt", reason="Windows system folders")
def test_refuses_windows_and_program_files(tmp_path):
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    assert _refused(system_root, home=str(tmp_path)) == "system_folder"
    assert _refused(os.path.join(system_root, "System32"), home=str(tmp_path)) == "system_folder"
    program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
    assert _refused(program_files, home=str(tmp_path)) == "system_folder"
    common = os.path.join(program_files, "Common Files")
    if os.path.isdir(common):
        assert _refused(common, home=str(tmp_path)) == "system_folder"
    pf86 = os.environ.get("ProgramFiles(x86)")
    if pf86 and os.path.isdir(pf86):
        assert _refused(pf86, home=str(tmp_path)) == "system_folder"


def test_refuses_vigils_own_install_and_data_folders(tmp_path, monkeypatch):
    install = _dir(tmp_path, "apps/Vigil")
    data = _dir(tmp_path, "local/V-LAW")
    own_paths._cache = [own_paths._norm(install), own_paths._norm(data)]
    try:
        home = str(tmp_path / "home")
        assert _refused(install, home=home) == "vigil_folder"
        assert _refused(_dir(tmp_path, "apps/Vigil/tray"), home=home) == "vigil_folder"
        assert _refused(data, home=home) == "vigil_folder"
        assert _refused(str(tmp_path / "apps"), home=home) == "vigil_folder", "a parent of Vigil's folder would watch it"
    finally:
        own_paths.reset_cache()


def test_refuses_folders_already_watched_by_the_built_in_rules(tmp_path):
    home = _dir(tmp_path, "home")
    ssh = _dir(tmp_path, "home/.ssh")
    assert _refused(ssh, home=home) == "already_watched_fixed"
    assert _refused(_dir(tmp_path, "home/.ssh/keys"), home=home) == "already_watched_fixed"
    cache = _dir(tmp_path, "home/.claude/file-history")
    assert _refused(cache, home=home) == "already_watched_fixed"


def test_refuses_duplicates_nested_and_parent_folders(tmp_path):
    home = str(tmp_path / "home")
    a = validate_new_folder(_dir(tmp_path, "work/app"), [], home=home)
    assert _refused(_dir(tmp_path, "work/app"), [a], home=home) == "duplicate"
    assert _refused(str(Path(a).as_posix()).upper(), [a], home=home) in ("duplicate", "not_found"), "case differences"
    assert _refused(_dir(tmp_path, "work/app/sub"), [a], home=home) == "inside_watched"
    assert _refused(_dir(tmp_path, "work"), [a], home=home) == "contains_watched"


def test_refuses_more_than_the_maximum_number_of_folders(tmp_path):
    home = str(tmp_path / "home")
    existing = []
    for i in range(MAX_FOLDERS):
        existing.append(validate_new_folder(_dir(tmp_path, f"projects/p{i:02d}"), existing, home=home))
    assert len(existing) == MAX_FOLDERS
    assert _refused(_dir(tmp_path, "projects2/extra"), existing, home=home) == "too_many"


# ---------------------------------------------------------------- the API

@pytest.mark.asyncio
async def test_api_refuses_requests_not_from_localhost(db, tmp_path):
    body = scope_api.ScopeRequest(path=_dir(tmp_path, "p"))
    for call in (scope_api.get_scope(REMOTE), scope_api.add_scope(body, REMOTE), scope_api.remove_scope(body, REMOTE)):
        with pytest.raises(HTTPException) as exc:
            await call
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_api_add_list_remove_persist_and_audit(db, tmp_path, monkeypatch):
    import main as main_module

    monkeypatch.setitem(main_module._state, "observer", None)
    monkeypatch.setitem(main_module._state, "file_handler", None)
    project = _dir(tmp_path, "client work/app")
    # keep the user's home out of the way of validation
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path / "home")))

    result = await scope_api.add_scope(scope_api.ScopeRequest(path=project), LOCAL)
    stored = Path(project).resolve().as_posix()
    assert result["path"] == stored and result["watching"] is False and result["note"]

    assert await get_scope_directories(db) == [stored]
    listing = await scope_api.get_scope(LOCAL)
    assert [f["path"] for f in listing["folders"]] == [stored]
    assert listing["folders"][0]["source"] == "user" and listing["folders"][0]["added_at"]

    cur = await db.execute("SELECT detail FROM audit_log WHERE action = 'scope_add' ORDER BY id DESC LIMIT 1")
    assert json.loads((await cur.fetchone())["detail"]) == {"path": stored}

    removed = await scope_api.remove_scope(scope_api.ScopeRequest(path=project), LOCAL)
    assert removed["folders"] == [] and await get_scope_directories(db) == []
    cur = await db.execute("SELECT detail FROM audit_log WHERE action = 'scope_remove' ORDER BY id DESC LIMIT 1")
    assert json.loads((await cur.fetchone())["detail"]) == {"path": stored}


@pytest.mark.asyncio
async def test_api_returns_clear_errors(db, tmp_path):
    project = _dir(tmp_path, "app")
    await scope_api.add_scope(scope_api.ScopeRequest(path=project), LOCAL)

    cases = [
        (str(tmp_path / "missing"), 400, "does not exist"),
        (project, 409, "already watched"),
        (_dir(tmp_path, "app/sub"), 409, "already covered"),
        (str(tmp_path), 409, "contains an already watched"),
        ("\\\\server\\share", 400, "Network"),
        ("", 400, "full path"),
    ]
    for path, status, text in cases:
        with pytest.raises(HTTPException) as exc:
            await scope_api.add_scope(scope_api.ScopeRequest(path=path), LOCAL)
        assert exc.value.status_code == status, path
        assert text.lower() in exc.value.detail.lower(), (path, exc.value.detail)

    with pytest.raises(HTTPException) as exc:
        await scope_api.remove_scope(scope_api.ScopeRequest(path=str(tmp_path / "not-watched")), LOCAL)
    assert exc.value.status_code == 404


class _EventLog(FileSystemEventHandler):
    def __init__(self):
        self.paths = []
        self.lock = threading.Lock()

    def on_any_event(self, event):
        if not event.is_directory:
            with self.lock:
                self.paths.append(event.dest_path or event.src_path)

    def seen(self, name):
        with self.lock:
            return any(os.path.basename(p) == name for p in self.paths)


def _wait_for(predicate, seconds=6.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@pytest.mark.asyncio
async def test_adding_a_folder_schedules_it_live_and_removing_stops_it(db, tmp_path, monkeypatch):
    import main as main_module

    observer, handler = Observer(), _EventLog()
    observer.start()
    monkeypatch.setitem(main_module._state, "observer", observer)
    monkeypatch.setitem(main_module._state, "file_handler", handler)
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path / "home")))
    project = _dir(tmp_path, "live project")
    try:
        before = Path(project) / "before.txt"
        before.write_text("x")
        time.sleep(0.5)
        assert not handler.seen("before.txt"), "nothing is watched until the folder is added"

        result = await scope_api.add_scope(scope_api.ScopeRequest(path=project), LOCAL)
        assert result["watching"] is True

        (Path(project) / "during.txt").write_text("x")
        assert _wait_for(lambda: handler.seen("during.txt")), "a file created after the add must produce an event, with no restart"

        removed = await scope_api.remove_scope(scope_api.ScopeRequest(path=project), LOCAL)
        assert removed["unwatched"] is True
        time.sleep(0.5)
        (Path(project) / "after.txt").write_text("x")
        time.sleep(1.5)
        assert not handler.seen("after.txt"), "after removal the folder is no longer watched"
    finally:
        observer.stop()
        observer.join(timeout=5)


def test_watch_and_unwatch_helpers_do_not_duplicate_a_watch(tmp_path):
    observer, handler = Observer(), _EventLog()
    observer.start()
    try:
        folder = _dir(tmp_path, "once")
        assert watch_folder(observer, handler, folder) is True
        assert watch_folder(observer, handler, folder) is True
        assert len(observer.emitters) == 1, "the same folder must not be scheduled twice (duplicate events)"
        assert unwatch_folder(observer, folder) is True
        assert unwatch_folder(observer, folder) is False
        assert watch_folder(object(), handler, folder) is False, "an observer without schedule() (ETW tier)"
    finally:
        observer.stop()
        observer.join(timeout=5)


# ---------------------------------------------------------------- reports

def _pdf_text(summary) -> str:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    async def fake_build_summary(date, tz=None):
        return dict(summary)

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
    return " ".join(drawn)


@pytest.mark.asyncio
async def test_reports_list_watched_folders_and_the_scope_note(db):
    await _set_scope(db, ["C:/Users/gbhid/vlaw", "D:/work/app"])
    summary = await export_module._build_summary("today")

    assert [f["path"] for f in summary["watched_folders"]] == ["C:/Users/gbhid/vlaw", "D:/work/app"]
    assert all(f["source"] == "user" for f in summary["watched_folders"])
    assert export_module.FILE_SCOPE_NOTE in summary["report_notes"]
    assert export_module.FILE_SCOPE_NOTE == (
        "Vigil only records file changes in watched folders, in ~/.ssh and in the Claude checkpoint cache. "
        "Changes elsewhere are not recorded."
    )

    text = _pdf_text(summary)
    assert "Watched folders (2):" in text
    assert "C:/Users/gbhid/vlaw" in text and "D:/work/app" in text
    assert "Changes elsewhere are not recorded." in text
    assert export_module.NO_WATCHED_FOLDERS_TEXT not in text


@pytest.mark.asyncio
async def test_reports_say_so_when_no_project_folders_are_watched(db):
    await _set_scope(db, [])
    summary = await export_module._build_summary("today")
    assert summary["watched_folders"] == []
    text = _pdf_text(summary)
    assert "No project folders are watched yet. Add one in Settings." in text
    assert "Watched folders (" not in text


@pytest.mark.asyncio
async def test_scope_note_changes_when_kernel_tracing_is_active(db):
    await _set_scope(db, [])
    set_file_watcher_tier("etw")
    notes = export_module.current_report_notes()
    assert export_module.FILE_SCOPE_NOTE not in notes and export_module.FILE_SCOPE_NOTE_ETW in notes
    summary = await export_module._build_summary("today")
    assert summary["file_watcher_tier"] == "etw"
    set_file_watcher_tier("folders")
    assert export_module.FILE_SCOPE_NOTE in export_module.current_report_notes()


# --------------------------------------------------------------------- UI

def test_settings_and_status_wording():
    src = Path(__file__).resolve().parents[2] / "frontend" / "src" / "components"
    if not src.exists():
        pytest.skip("frontend sources not present")
    settings = (src / "Settings.jsx").read_text(encoding="utf-8")
    assert "Watched folders" in settings and "Add folder" in settings and "Remove" in settings
    assert "does not read, copy or store file contents" in settings
    assert "No project folders are watched yet. Add one below." in settings
    status = (src / "Status.jsx").read_text(encoding="utf-8")
    assert "No project folders are watched yet." in status and "Add one in Settings" in status
