"""Watcher-level ignore of generated folders (core/ignore_rules.py), the
bound on raw events, the report wording, the real-repository load test, and
the "session ran with no watched folder" flag. See conftest.py for why
VLAW_DATA_DIR is set there rather than here."""

import asyncio
import os
import threading
import time
import types
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from watchdog.observers import Observer

import api.export as export_module
import api.scope as scope_api
import core.own_paths as own_paths
import core.scope_store as scope_store
import db.database as database
import watchers.file_watcher as file_watcher
from core import ignore_rules, watch_stats
from core.ignore_rules import ignored_folder_for
from core.monitoring_status import set_file_watcher_tier

LOCAL = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))


@pytest.fixture(autouse=True)
def _clean_counters():
    watch_stats.reset()
    yield
    watch_stats.reset()
    set_file_watcher_tier("folders")


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    """Scope rows saved and restored; policy file pointed at a missing file;
    LOCALAPPDATA redirected so nothing here can write into the real V-LAW
    folder (the aggregator's crash-recovery log lives there)."""
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
    own_paths.reset_cache()
    await database.close_db()


# ------------------------------------------------------------- the rule

@pytest.mark.parametrize("path, folder", [
    ("C:/proj/node_modules/left-pad/index.js", "node_modules"),
    ("C:\\proj\\node_modules\\a\\b.js", "node_modules"),
    ("C:/proj/Node_Modules/a.js", "node_modules"),
    ("C:/proj/.venv/Lib/site.py", ".venv"),
    ("C:/proj/venv/bin/python", "venv"),
    ("C:/proj/src/__pycache__/m.cpython-313.pyc", "__pycache__"),
    ("C:/proj/dist/app.js", "dist"),
    ("C:/proj/build/out.o", "build"),
    ("C:/proj/web/.next/cache/x", ".next"),
    ("C:/proj/target/debug/app.exe", "target"),
    ("C:/proj/.pytest_cache/v/cache/nodeids", ".pytest_cache"),
    ("C:/proj/.mypy_cache/3.13/x.json", ".mypy_cache"),
    ("C:/proj/.tox/py313/lib/x.py", ".tox"),
    ("C:/proj/coverage/lcov.info", "coverage"),
    ("C:/proj/.cache/x", ".cache"),
])
def test_generated_and_dependency_folders_are_ignored(path, folder):
    assert ignored_folder_for(path) == folder


@pytest.mark.parametrize("path", [
    "C:/proj/src/app.py", "C:/proj/src/build.py", "C:/proj/buildings/plan.txt", "C:/proj/distribution/x.md",
    "C:/proj/.github/workflows/ci.yml", "C:/proj/.gitignore", "C:/proj/.gitmodules", "C:/proj/targets/x",
    "", None,
])
def test_ordinary_paths_are_recorded(path):
    assert ignored_folder_for(path) is None


@pytest.mark.parametrize("path", [
    "C:/proj/.git/objects/ab/cdef", "C:/proj/.git/refs/heads/main", "C:/proj/.git/logs/HEAD",
    "C:/proj/.git/index", "C:/proj/.git/packed-refs", "C:/proj/.git/objects/pack/pack-1.pack",
    "C:/proj/.git/config.lock", "C:/proj/.git/HEAD", "C:/proj/.git/modules/sub/objects/ab/cd",
])
def test_most_of_dot_git_is_ignored(path):
    assert ignored_folder_for(path) == ".git"


@pytest.mark.parametrize("path", [
    "C:/proj/.git/hooks/pre-commit", "C:\\proj\\.git\\hooks\\post-checkout", "C:/proj/.git/config",
    "C:/proj/.git/modules/sub/hooks/pre-push", "C:/proj/.git/modules/sub/config", "C:/proj/.gitmodules",
])
def test_security_relevant_git_paths_are_never_ignored(path):
    assert ignored_folder_for(path) is None


@pytest.mark.parametrize("path", [
    "C:/proj/node_modules/pkg/.env", "C:/proj/build/secrets.pem", "C:/proj/dist/deploy.key",
    "C:/proj/.venv/.ssh/id_rsa", "C:/proj/target/.aws/credentials", "C:/proj/node_modules/.env.local",
])
def test_env_and_credential_files_are_never_ignored_anywhere(path):
    assert ignored_folder_for(path) is None
    assert ignore_rules.ignore_and_count(path) is False
    assert watch_stats.ignored_total() == 0


def test_ignoring_counts_per_folder_and_can_be_switched_off(monkeypatch):
    for path in ("a/node_modules/x", "a/node_modules/y", "a/dist/z", "a/.git/objects/q"):
        assert ignore_rules.ignore_and_count(path) is True
    assert watch_stats.ignored_by_folder() == {"node_modules": 2, "dist": 1, ".git": 1}
    assert watch_stats.ignored_total() == 4

    monkeypatch.setenv("VLAW_IGNORE_GENERATED", "0")
    assert ignore_rules.ignore_and_count("a/node_modules/x") is False
    assert watch_stats.ignored_total() == 4


# ------------------------------------------- applied at every entry point

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


def _fs_event(path, kind="modified"):
    return types.SimpleNamespace(is_directory=False, event_type=kind, src_path=path, dest_path="")


def _handler(loop=None):
    return file_watcher.VlawFileHandler(_Attributor(), object(), loop or asyncio.new_event_loop(), pid_cache=None)


class _FakeFuture:
    def __init__(self):
        self.callbacks = []

    def add_done_callback(self, cb):
        self.callbacks.append(cb)

    def exception(self):
        return None

    def cancelled(self):
        return False


def test_native_and_polling_observers_drop_ignored_events_before_any_work(monkeypatch):
    scheduled = []

    def fake_submit(coro, loop):
        scheduled.append(coro)
        coro.close()
        return _FakeFuture()

    monkeypatch.setattr(file_watcher.asyncio, "run_coroutine_threadsafe", fake_submit)
    handler = _handler()
    handler.on_any_event(_fs_event("C:/proj/node_modules/a/b.js"))
    handler.on_any_event(_fs_event("C:/proj/.git/objects/ab/cd"))
    assert scheduled == [] and watch_stats.ignored_total() == 2

    handler.on_any_event(_fs_event("C:/proj/src/app.py"))
    handler.on_any_event(_fs_event("C:/proj/.git/hooks/pre-commit"))
    handler.on_any_event(_fs_event("C:/proj/node_modules/x/.env"))
    assert len(scheduled) == 3 and watch_stats.ignored_total() == 2


def test_handle_file_event_is_a_safety_net(monkeypatch):
    handler = _handler()
    recorded = []

    async def record_event(path, event_type):
        recorded.append(path)

    handler._burst_detector.record_event = record_event
    asyncio.run(handler.handle_file_event("C:/proj/node_modules/x.js", "file_write", "etw", 1, "high"))
    assert recorded == [] and watch_stats.ignored_total() == 1


def test_etw_tier_drops_ignored_events_before_attribution(monkeypatch):
    from watchers import etw_file_watcher as etw

    looked_up, dispatched = [], []

    class Attrib:
        def get_agent_for_pid(self, pid):
            looked_up.append(pid)
            return "claude_code"

    watcher = etw.ETWFileWatcher(Attrib())
    monkeypatch.setattr(watcher, "_dispatch", lambda pid, path, kind, ts: dispatched.append(path))

    def make_event(path):
        return types.SimpleNamespace(
            event_id=etw.TASK_WRITE, process_id=4242, timestamp_unix=1.0,
            get_u64=lambda name: 77, get_string=lambda name: path,
        )

    watcher._process_event(make_event("C:\\proj\\node_modules\\a\\b.js"))
    assert looked_up == [] and dispatched == [] and watch_stats.ignored_total() == 1

    watcher._process_event(make_event("C:\\proj\\src\\app.py"))
    assert looked_up == [4242] and dispatched == ["C:\\proj\\src\\app.py"]


# ----------------------------------------------------------- the bound

def test_raw_event_dispatch_is_bounded_and_drops_are_counted(monkeypatch):
    futures = []

    def fake_submit(coro, loop):
        coro.close()
        f = _FakeFuture()
        futures.append(f)
        return f

    monkeypatch.setattr(file_watcher.asyncio, "run_coroutine_threadsafe", fake_submit)
    monkeypatch.setattr(file_watcher, "MAX_PENDING_FILE_DISPATCH", 5)
    handler = _handler()

    for i in range(8):
        handler.on_any_event(_fs_event(f"C:/proj/src/f{i}.py"))
    assert len(futures) == 5 and watch_stats.dropped_total() == 3

    for f in futures[:2]:                      # two handled: room for two more
        for cb in f.callbacks:
            cb(f)
    for i in range(8, 12):
        handler.on_any_event(_fs_event(f"C:/proj/src/f{i}.py"))
    assert len(futures) == 7 and watch_stats.dropped_total() == 3 + 2


@pytest.mark.asyncio
async def test_a_full_event_buffer_counts_what_it_drops(db, tmp_path):
    from core import aggregator as aggregator_module

    agg = aggregator_module.Aggregator()
    agg._append_crash_recovery_line = lambda event: None
    for i in range(aggregator_module.FILE_EVENT_BUFFER_MAX + 3):
        await agg.buffer_file_event({"path": f"p{i}"})
    assert len(agg.file_event_buffer) == aggregator_module.FILE_EVENT_BUFFER_MAX
    assert watch_stats.dropped_total() == 3


# ---------------------------------------------------------------- report

@pytest.mark.asyncio
async def test_report_states_ignored_and_dropped_counts_only_when_nonzero_and_active(db, monkeypatch):
    base = export_module.current_report_notes()
    assert not any("generated or dependency folders" in n for n in base)
    assert not any("arrived at once" in n for n in base)

    for _ in range(7):
        ignore_rules.ignore_and_count("p/node_modules/x")
    notes = export_module.current_report_notes()
    assert "7 changes in generated or dependency folders (node_modules, build outputs) were not recorded." in notes

    summary = await export_module._build_summary("today")
    assert summary["ignored_generated_changes"] == 7 and summary["ignored_by_folder"] == {"node_modules": 7}
    assert "7 changes in generated or dependency folders (node_modules, build outputs) were not recorded." in summary["report_notes"]

    monkeypatch.setenv("VLAW_IGNORE_GENERATED", "0")        # rule switched off: no sentence
    assert not any("generated or dependency folders" in n for n in export_module.current_report_notes())

    watch_stats.add_dropped("overload")
    assert "1 file changes were not recorded because too many arrived at once." in export_module.current_report_notes()


def test_coverage_doc_describes_the_ignore_rule():
    doc = (Path(__file__).resolve().parents[2] / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert "were not recorded." in doc and "node_modules" in doc and ".git/hooks" in doc


# --------------------------------------------- unwatched sessions (part 2)

async def _session_with(db, *, procs=0, file_events=0):
    name = f"claude_code_unwatched_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name))
    agent_id = cur.lastrowid
    sid = f"sess_{uuid.uuid4().hex[:8]}"
    await db.execute("INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (sid, agent_id))
    for _ in range(procs):
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'proc_spawn', 'git.exe', '{}')",
            (agent_id, sid),
        )
    for i in range(file_events):
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'file_write', ?)",
            (agent_id, sid, f"C:/proj/f{i}.py"),
        )
    await db.commit()
    return agent_id, sid


async def _session_summary(sid):
    summary = await export_module._build_summary("today")
    return summary, next(s for s in summary["sessions"] if s["id"] == sid)


async def _cleanup(db, agent_id):
    await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
    await db.commit()


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
async def test_session_with_processes_but_no_file_events_and_no_watched_folder_is_flagged(db):
    await scope_store.save_scope(db, [], {})
    agent_id, sid = await _session_with(db, procs=3)
    try:
        summary, session = await _session_summary(sid)
        assert session["unwatched_session"] is True
        text = _pdf_text(summary)
        assert "(info: no project folder is watched, so file changes by this session were not recorded)" in text
    finally:
        await _cleanup(db, agent_id)


@pytest.mark.asyncio
async def test_unwatched_flag_is_false_in_every_other_case(db, tmp_path):
    await scope_store.save_scope(db, [], {})
    ran_and_wrote, quiet = await _session_with(db, procs=2, file_events=1), await _session_with(db, procs=0)
    try:
        assert (await _session_summary(ran_and_wrote[1]))[1]["unwatched_session"] is False   # it had file events
        assert (await _session_summary(quiet[1]))[1]["unwatched_session"] is False           # ran no processes

        # A watched folder exists and the session simply made no file changes: not flagged, no line.
        await scope_store.save_scope(db, ["C:/Users/someone/project"], {})
        agent_id, sid = await _session_with(db, procs=3)
        try:
            summary, session = await _session_summary(sid)
            assert session["unwatched_session"] is False
            assert "no project folder is watched" not in _pdf_text(summary)
        finally:
            await _cleanup(db, agent_id)

        # Kernel tracing active: file changes are recorded everywhere, so no explanation is needed.
        await scope_store.save_scope(db, [], {})
        set_file_watcher_tier("etw")
        agent_id, sid = await _session_with(db, procs=3)
        try:
            assert (await _session_summary(sid))[1]["unwatched_session"] is False
        finally:
            await _cleanup(db, agent_id)
    finally:
        await _cleanup(db, ran_and_wrote[0])
        await _cleanup(db, quiet[0])


@pytest.mark.asyncio
async def test_unwatched_session_is_an_info_line_not_an_alert(db):
    await scope_store.save_scope(db, [], {})
    agent_id, sid = await _session_with(db, procs=3)
    try:
        await _session_summary(sid)
        cur = await db.execute("SELECT COUNT(*) c FROM alerts WHERE agent_id = ?", (agent_id,))
        assert (await cur.fetchone())["c"] == 0
    finally:
        await _cleanup(db, agent_id)


# ------------------------------------------------- real repository load test

class _LoopMonitor:
    """Max extra delay of a 50 ms sleep, i.e. how long the loop was blocked."""

    def __init__(self):
        self.max_delay = 0.0
        self._stop = False
        self.task = None

    async def _run(self):
        while not self._stop:
            start = time.perf_counter()
            await asyncio.sleep(0.05)
            self.max_delay = max(self.max_delay, time.perf_counter() - start - 0.05)

    def start(self):
        self.task = asyncio.create_task(self._run())

    async def stop(self):
        self._stop = True
        await self.task


def _populate(repo: Path, packages: int, per_package: int, git_dirs: int, per_git_dir: int) -> int:
    count = 0
    for p in range(packages):
        d = repo / "node_modules" / f"pkg{p:04d}"
        d.mkdir(parents=True, exist_ok=True)
        for f in range(per_package):
            (d / f"f{f}.js").write_text("x")
            count += 1
    for g in range(git_dirs):
        d = repo / ".git" / "objects" / f"{g:02x}"
        d.mkdir(parents=True, exist_ok=True)
        for f in range(per_git_dir):
            (d / f"o{f:04d}").write_text("x")
            count += 1
    return count


def _modify_all(repo: Path) -> int:
    count = 0
    for root in (repo / "node_modules", repo / ".git" / "objects"):
        for path in root.rglob("*"):
            if path.is_file():
                with open(path, "a") as fh:
                    fh.write("y")
                count += 1
    return count


@pytest.mark.asyncio
async def test_real_repository_layout_burst_is_ignored_cheaply_and_recorded_where_it_matters(db, tmp_path, monkeypatch, capsys):
    import main as main_module
    from core.aggregator import Aggregator

    started = time.perf_counter()
    repo = tmp_path / "bigrepo"
    (repo / "src").mkdir(parents=True)
    (repo / ".git" / "hooks").mkdir(parents=True)
    (repo / ".git" / "config").write_text("[core]\n")

    name = f"claude_code_load_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name))
    agent_id = cur.lastrowid
    session_id = f"load_{uuid.uuid4().hex[:8]}"
    await db.commit()

    class Attributor(_Attributor):
        class sessions:
            @staticmethod
            async def touch(aid, resumed=False):
                return session_id

        async def get_or_create_agent(self, n, pid=None, confidence=None):
            return agent_id

    async def fixed_pid(pid_cache, path=None):
        return 4242, "high"

    monkeypatch.setattr(file_watcher, "_find_owning_agent_pid", fixed_pid)

    aggregator = Aggregator()
    aggregator._writer_task = asyncio.create_task(aggregator.start_writer())
    loop = asyncio.get_running_loop()
    handler = file_watcher.VlawFileHandler(Attributor(), aggregator, loop, pid_cache=None, use_pid_heuristic=True)
    observer = Observer()
    observer.start()
    monkeypatch.setitem(main_module._state, "observer", observer)
    monkeypatch.setitem(main_module._state, "file_handler", handler)

    monitor = _LoopMonitor()
    try:
        result = await scope_api.add_scope(scope_api.ScopeRequest(path=str(repo)), LOCAL)
        assert result["watching"] is True
        monitor.start()

        # 1. real source files: must be recorded
        for i in range(20):
            (repo / "src" / f"module{i:02d}.py").write_text("print(1)")

        def src_paths():
            return {e["path"] for e in aggregator.file_event_buffer if "/src/" in e["path"].replace("\\", "/")}

        deadline = time.time() + 15
        while time.time() < deadline and len({os.path.basename(p) for p in src_paths()}) < 20:
            await asyncio.sleep(0.1)
        assert len({os.path.basename(p) for p in src_paths()}) == 20, "all 20 src files must produce events"

        # 2. the burst: 20,000 node_modules files + 5,000 .git/objects files, created then modified
        created = await asyncio.to_thread(_populate, repo, 200, 100, 50, 100)
        modified = await asyncio.to_thread(_modify_all, repo)

        last, stable_since = -1, time.time()
        deadline = time.time() + 90
        while time.time() < deadline:
            await asyncio.sleep(0.25)
            total = watch_stats.ignored_total()
            if total != last:
                last, stable_since = total, time.time()
            elif time.time() - stable_since > 2.0:
                break
        ignored = watch_stats.ignored_total()
        by_folder = watch_stats.ignored_by_folder()

        # 3. security-relevant git paths must still be recorded
        (repo / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\n")
        with open(repo / ".git" / "config", "a") as fh:
            fh.write("[alias]\n")
        deadline = time.time() + 15

        def has(suffix):
            return any(e["path"].replace("\\", "/").endswith(suffix) for e in aggregator.file_event_buffer)

        while time.time() < deadline and not (has("/.git/hooks/pre-commit") and has("/.git/config")):
            await asyncio.sleep(0.1)
        assert has("/.git/hooks/pre-commit") and has("/.git/config")

        await monitor.stop()
        await aggregator.flush_buffers()

        cur = await db.execute("SELECT path FROM events WHERE session_id = ? AND agent_id = ?", (session_id, agent_id))
        paths = [r["path"].replace("\\", "/") for r in await cur.fetchall()]
        assert len({os.path.basename(p) for p in paths if "/src/" in p}) == 20
        assert any(p.endswith("/.git/hooks/pre-commit") for p in paths) and any(p.endswith("/.git/config") for p in paths)
        assert [p for p in paths if "/node_modules/" in p or "/.git/objects/" in p] == [], "ignored folders must produce no rows"
        assert ignored > 0 and by_folder.get("node_modules", 0) > 0

        elapsed = time.perf_counter() - started
        with capsys.disabled():
            print(
                f"\n[load test] files created={created} modified={modified} "
                f"ignored_events={ignored} {by_folder} recorded_rows={len(paths)} "
                f"max_loop_delay={monitor.max_delay * 1000:.0f}ms elapsed={elapsed:.1f}s dropped={watch_stats.dropped_total()}"
            )
        assert monitor.max_delay < 1.0, f"event loop blocked for {monitor.max_delay:.2f}s"
        assert elapsed < 150
    finally:
        if not monitor._stop and monitor.task is not None:
            await monitor.stop()
        observer.stop()
        observer.join(timeout=10)
        await aggregator.stop_writer()
        await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
        await db.commit()
