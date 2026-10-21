"""The ETW tier must decide from memory, before any database access, whether an event matters: a recognised agent's
app (Claude desktop) writing its own cache and crash-report files produced thousands of events a second, and each one
cost an agent lookup, a SELECT, an UPDATE and a commit on the shared connection, which stalled the aggregator's writes
(write_batch took 168 s for 19 events on a real machine). These tests cover the filter, the device-path conversion,
the agent-id cache, the dropped-event reporting, the tier switch, the installer flag and a sustained load.
See conftest.py for why VLAW_DATA_DIR is set there rather than here."""

import asyncio
import os
import re
import threading
import time
import types
from pathlib import Path

import pytest
import pytest_asyncio

import core.device_paths as device_paths
import db.database as database
import watchers.etw_file_watcher as etw
import watchers.file_watcher as file_watcher
from core import mcp_service, report_coverage, watch_stats
from core.aggregator import Aggregator
from core.attributor import AGENT_LAST_SEEN_WRITE_SECONDS, Attributor
from core.device_paths import normalise_device_path
from core.monitoring_status import set_file_watcher_tier
from core.scope_filter import ScopeFilter

ROOT = Path(__file__).resolve().parents[2]
HOME = r"C:\Users\dev"
VOLUME = {"\\device\\harddiskvolume3": "C:", "\\device\\harddiskvolume5": "D:"}

CLAUDE_DESKTOP = r"\Device\HarddiskVolume3\Users\dev\AppData\Roaming\Claude\Claude-Data\0a1b2c.tmp"
SENTRY = r"\Device\HarddiskVolume3\Users\dev\AppData\Roaming\Claude\sentry\scope_v3.json"
NPM_LOG = r"\Device\HarddiskVolume3\Users\dev\AppData\Local\npm-cache\_logs\2026-10-21T10_00_00_000Z-debug-0.log"


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    real = os.path.expanduser
    monkeypatch.setattr(os.path, "expanduser", lambda p: HOME if p == "~" else real(p))
    monkeypatch.setattr(file_watcher, "CORE_ONLY", True)
    monkeypatch.setattr(device_paths, "_query_dos_devices", lambda: dict(VOLUME))
    monkeypatch.setattr(device_paths, "_built_at", 0.0)
    monkeypatch.setattr(device_paths, "_map", {})
    watch_stats.reset()
    yield
    watch_stats.reset()
    set_file_watcher_tier("folders")


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "vlaw.db")
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


def project_scope() -> ScopeFilter:
    scope = ScopeFilter()
    scope.set_roots([r"C:\proj", "~/.aws"])
    return scope


# ------------------------------------------------------------------ the filter

def test_the_filter_lets_through_watched_roots_credentials_and_agent_state_and_nothing_else():
    scope = project_scope()
    assert scope.allows(r"C:\proj\src\app.py") and scope.allows("c:/PROJ/src/app.py") and scope.allows(r"C:\proj")
    assert scope.allows(r"C:\Users\dev\.aws\credentials")
    assert scope.allows(r"C:\work\other\.env") and scope.allows(r"C:\Users\dev\.ssh\id_rsa") and scope.allows(r"D:\certs\server.pem")
    assert scope.allows(r"C:\Users\dev\.claude\file-history\abc\def@v1") and scope.allows("C:/Users/dev/.codex/config.toml")
    for outside in (r"C:\Users\dev\AppData\Roaming\Claude\Claude-Data\0a1b2c.tmp", r"C:\Users\dev\AppData\Roaming\Claude\sentry\scope_v3.json",
                    r"C:\Users\dev\AppData\Local\npm-cache\_logs\debug-0.log", r"C:\proj2\src\app.py", r"C:\projects\app.py",
                    r"C:\Users\other\.claude\x", r"C:\Windows\Temp\a.tmp"):
        assert not scope.allows(outside), outside


def test_a_filter_that_has_not_been_given_its_roots_yet_lets_everything_through():
    scope = ScopeFilter()
    assert not scope.loaded and scope.allows(r"C:\anything\at\all.txt")
    scope.set_roots([])
    assert scope.loaded and not scope.allows(r"C:\anything\at\all.txt"), "an empty list of folders is a real answer"


def test_roots_can_be_added_and_removed_while_running():
    scope = ScopeFilter()
    scope.set_roots([r"C:\a"])
    scope.add_root(r"C:\b")
    assert scope.allows(r"C:\b\x.py")
    scope.remove_root(r"C:\a")
    assert not scope.allows(r"C:\a\x.py") and scope.allows(r"C:\b\x.py")


# ------------------------------------------------------------------ device paths

@pytest.mark.parametrize("raw, expected", [
    (r"\Device\HarddiskVolume3\Users\dev\a.txt", r"C:\Users\dev\a.txt"),
    (r"\DEVICE\HARDDISKVOLUME5\x\y.py", r"D:\x\y.py"),
    (r"\Device\HarddiskVolume3", "C:"),
    (r"\Device\Mup\server\share\f.txt", r"\\server\share\f.txt"),
    (r"\??\C:\Users\dev\a.txt", r"C:\Users\dev\a.txt"),
    (r"\\?\C:\Users\dev\a.txt", r"C:\Users\dev\a.txt"),
    (r"\??\UNC\server\share\f.txt", r"\\server\share\f.txt"),
    (r"C:\Users\dev\already.txt", r"C:\Users\dev\already.txt"),
    (r"\Device\HarddiskVolume9\unknown.txt", r"\Device\HarddiskVolume9\unknown.txt"),     # not guessed at
    (r"\Device\HarddiskVolume33\x", r"\Device\HarddiskVolume33\x"),                      # a different volume, not a prefix match
])
def test_device_paths_become_drive_letter_paths_and_unknown_ones_are_left_alone(raw, expected):
    assert normalise_device_path(raw, VOLUME) == expected


def test_empty_and_non_device_input_is_returned_as_it_is():
    assert normalise_device_path(None) is None and normalise_device_path("") == ""
    assert normalise_device_path("relative/path.txt") == "relative/path.txt"


def test_the_real_map_is_used_when_none_is_given_and_a_new_volume_is_picked_up():
    assert normalise_device_path(r"\Device\HarddiskVolume3\a") == r"C:\a"
    VOLUME["\\device\\harddiskvolume7"] = "E:"
    try:
        device_paths._built_at = 0.0          # the rate limit has passed
        assert normalise_device_path(r"\Device\HarddiskVolume7\a") == r"E:\a"
    finally:
        VOLUME.pop("\\device\\harddiskvolume7", None)


# ------------------------------------------------------------------ the ETW thread's decision

class FakeEvent:
    def __init__(self, path, pid, event_id=etw.TASK_WRITE, file_object=1):
        self.event_id, self.process_id, self._path, self._fo = event_id, pid, path, file_object
        self.timestamp_unix = time.time()

    def get_u64(self, name):
        return self._fo

    def get_string(self, name):
        return self._path if name == "FileName" else None


class SpyAttributor:
    """get_agent_for_pid is what costs: count how often it is asked."""

    def __init__(self, agent_pids):
        self.agent_pids = agent_pids
        self.lookups = 0

    def get_agent_for_pid(self, pid):
        self.lookups += 1
        return self.agent_pids.get(pid)


def make_watcher(attributor, scope=None):
    watcher = etw.ETWFileWatcher(attributor, scope=scope or project_scope())
    seen = []
    watcher._dispatch = lambda pid, path, event_type, timestamp, change=None: seen.append((pid, path, event_type))
    return watcher, seen


def test_a_claude_desktop_file_outside_every_watched_place_is_counted_and_never_looked_up_or_dispatched():
    attributor = SpyAttributor({4242: "claude_code"})          # the app resolves to an agent by name
    watcher, seen = make_watcher(attributor)
    for path in (CLAUDE_DESKTOP, SENTRY, NPM_LOG):
        watcher._process_event(FakeEvent(path, 4242))
    assert seen == [] and attributor.lookups == 0, "decided from memory, before the agent lookup"
    assert watch_stats.out_of_scope_total() == 3


def test_in_scope_credential_and_agent_state_events_still_go_on_with_drive_letter_paths():
    attributor = SpyAttributor({4242: "claude_code"})
    watcher, seen = make_watcher(attributor)
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume3\proj\src\app.py", 4242))
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume3\Users\dev\.ssh\config", 4242))
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume3\Users\dev\.claude\file-history\x\y@v1", 4242))
    assert [p for _pid, p, _t in seen] == [r"C:\proj\src\app.py", r"C:\Users\dev\.ssh\config", r"C:\Users\dev\.claude\file-history\x\y@v1"]
    assert watch_stats.out_of_scope_total() == 0


def test_the_scope_check_uses_the_converted_path_so_a_raw_device_path_cannot_slip_past_or_be_wrongly_dropped():
    watcher, seen = make_watcher(SpyAttributor({1: "claude_code"}))
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume3\proj\a.py", 1))          # inside C:\proj
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume5\proj\a.py", 1))          # D:\proj: not watched
    assert [p for _pid, p, _t in seen] == [r"C:\proj\a.py"]


def test_a_file_object_seeded_with_a_device_path_is_resolved_to_the_drive_letter_path():
    watcher, seen = make_watcher(SpyAttributor({1: "claude_code"}))
    watcher._process_event(FakeEvent(r"\Device\HarddiskVolume3\proj\later.py", 1, event_id=etw.TASK_CREATE, file_object=77))
    path_less = FakeEvent(None, 1, event_id=etw.TASK_WRITE, file_object=77)
    watcher._process_event(path_less)
    assert [p for _pid, p, _t in seen] == [r"C:\proj\later.py"]


# ------------------------------------------------------------------ persistence locations are recorded

PERSISTENCE_WRITES = [
    r"C:\Users\dev\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat",
    r"C:\Users\dev\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sub\tool.lnk",
    r"C:\Users\dev\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    r"C:\Users\dev\Documents\WindowsPowerShell\profile.ps1",
    r"C:\Users\dev\Documents\PowerShell\profile.ps1",
    r"C:\Users\dev\Documents\PowerShell\Microsoft.VSCode_profile.ps1",
    r"C:\Users\dev\OneDrive\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    r"C:\Users\dev\.bashrc",
    r"C:\Users\dev\.bash_profile",
    r"C:\Users\dev\.bash_login",
    r"C:\Users\dev\.profile",
    r"C:\Users\dev\.zshrc",
    r"C:\Users\dev\.zprofile",
    r"C:\Users\dev\.zshenv",
    r"C:\Users\dev\.gitconfig",
]
NOT_PERSISTENCE = [
    r"C:\Users\dev\Documents\notes.ps1",
    r"C:\Users\dev\Documents\WindowsPowerShell\Modules\x\x.psm1",
    r"C:\Users\dev\Documents\Reports\profile.ps1",
    r"C:\Users\dev\.bashrc.bak",
    r"C:\Users\dev\work\.bashrc",
    r"C:\Users\other\.bashrc",
    r"C:\Users\dev\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\x.lnk",
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\machine.bat",
]


@pytest.fixture
def appdata(monkeypatch):
    monkeypatch.setenv("APPDATA", r"C:\Users\dev\AppData\Roaming")


@pytest.mark.parametrize("path", PERSISTENCE_WRITES)
def test_the_filter_lets_every_persistence_location_through(appdata, path):
    assert project_scope().allows(path), path
    assert project_scope().allows(path.upper()) and project_scope().allows(path.replace("\\", "/"))


@pytest.mark.parametrize("path", NOT_PERSISTENCE)
def test_lookalikes_of_the_persistence_locations_are_still_counted_and_dropped(appdata, path):
    assert not project_scope().allows(path), path


@pytest.mark.parametrize("path", PERSISTENCE_WRITES)
def test_an_etw_write_to_each_persistence_location_is_dispatched_to_be_recorded(appdata, path):
    device = path.replace("C:", r"\Device\HarddiskVolume3", 1)
    watcher, seen = make_watcher(SpyAttributor({4242: "claude_code"}))
    watcher._process_event(FakeEvent(device, 4242))
    assert [p for _pid, p, _t in seen] == [path]
    assert watch_stats.out_of_scope_total() == 0


@pytest.mark.asyncio
async def test_a_write_to_each_persistence_location_reaches_the_event_buffer_under_the_agent(db, appdata, monkeypatch):
    attributor = Attributor()
    monkeypatch.setattr(attributor, "get_agent_for_pid", lambda pid: "claude_code")
    aggregator = Aggregator()
    handler = file_watcher.VlawFileHandler(attributor, aggregator, asyncio.get_running_loop(), pid_cache=None)
    events = [FakeEvent(path.replace("C:", r"\Device\HarddiskVolume3", 1), 4242) for path in PERSISTENCE_WRITES]
    await run_events(events, handler, asyncio.get_running_loop(), attributor)
    recorded = {e["path"] for e in aggregator.file_event_buffer}
    assert recorded == set(PERSISTENCE_WRITES)
    assert {e["event_source"] for e in aggregator.file_event_buffer} == {"etw"}


# ------------------------------------------------------------------ database writes

class CountingDB:
    """Wraps the real connection and counts what writes."""

    def __init__(self, real):
        self._real = real
        self.writes = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def execute(self, sql, *args, **kwargs):
        if sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            self.writes.append(sql.split()[0].upper())
        return await self._real.execute(sql, *args, **kwargs)

    async def executemany(self, sql, *args, **kwargs):
        self.writes.append("EXECUTEMANY")
        return await self._real.executemany(sql, *args, **kwargs)

    async def commit(self):
        self.writes.append("COMMIT")
        return await self._real.commit()


async def run_events(watcher_events, handler, loop, attributor):
    """Feeds events through a real ETWFileWatcher whose dispatch runs the handler directly on this loop."""
    watcher = etw.ETWFileWatcher(attributor, scope=project_scope())
    watcher.set_callback(handler.handle_etw_event)
    watcher._loop = loop
    for event in watcher_events:
        watcher._process_event(event)
    for _ in range(200):
        if watcher._inflight._value == etw.MAX_INFLIGHT_EVENTS:
            break
        await asyncio.sleep(0.05)
    return watcher


@pytest.mark.asyncio
async def test_a_thousand_events_from_a_non_agent_pid_make_no_database_writes_at_all(db):
    counting = CountingDB(db)
    database._db = counting
    real_attributor = Attributor()
    attributor = types.SimpleNamespace(get_agent_for_pid=lambda pid: None)
    handler = file_watcher.VlawFileHandler(real_attributor, Aggregator(), asyncio.get_running_loop(), pid_cache=None)
    events = [FakeEvent(rf"\Device\HarddiskVolume3\proj\src\f{i}.py", 999) for i in range(1000)]     # in scope, but not an agent
    await run_events(events, handler, asyncio.get_running_loop(), attributor)
    assert counting.writes == []


@pytest.mark.asyncio
async def test_a_thousand_out_of_scope_events_from_an_agent_pid_make_no_database_writes_at_all(db):
    counting = CountingDB(db)
    database._db = counting
    real_attributor = Attributor()
    spy = SpyAttributor({4242: "claude_code"})
    handler = file_watcher.VlawFileHandler(real_attributor, Aggregator(), asyncio.get_running_loop(), pid_cache=None)
    events = [FakeEvent(rf"\Device\HarddiskVolume3\Users\dev\AppData\Roaming\Claude\Claude-Data\{i:06d}.tmp", 4242) for i in range(1000)]
    await run_events(events, handler, asyncio.get_running_loop(), spy)
    assert counting.writes == [] and spy.lookups == 0 and watch_stats.out_of_scope_total() == 1000


@pytest.mark.asyncio
async def test_a_thousand_in_scope_events_from_one_agent_cost_a_handful_of_writes_not_three_per_event(db, monkeypatch):
    counting = CountingDB(db)
    database._db = counting
    real_attributor = Attributor()
    monkeypatch.setattr(real_attributor, "get_agent_for_pid", lambda pid: "claude_code")
    aggregator = Aggregator()
    handler = file_watcher.VlawFileHandler(real_attributor, aggregator, asyncio.get_running_loop(), pid_cache=None)
    events = [FakeEvent(rf"\Device\HarddiskVolume3\proj\src\f{i}.py", 4242) for i in range(1000)]
    await run_events(events, handler, asyncio.get_running_loop(), real_attributor)
    # first sight of the agent (insert, approval lookup is a SELECT) and the one session it opens; nothing per event
    assert len(counting.writes) <= 8, counting.writes
    assert len(aggregator.file_event_buffer) == 1000


# ------------------------------------------------------------------ the agent-id cache

@pytest.mark.asyncio
async def test_agent_ids_are_remembered_and_last_seen_is_written_at_most_once_a_minute(db):
    counting = CountingDB(db)
    database._db = counting
    attributor = Attributor()
    first = await attributor.get_or_create_agent("claude_code", 100)
    writes_after_first = len(counting.writes)
    for pid in range(101, 1101):
        assert await attributor.get_or_create_agent("claude_code", pid) == first
    assert len(counting.writes) == writes_after_first, "1,000 more calls: no INSERT, UPDATE or commit"

    # after the interval it is written once, without a SELECT, and the pid is current again
    attributor._agent_cache["ids"]["claude_code"] = (first, time.monotonic() - AGENT_LAST_SEEN_WRITE_SECONDS - 1)
    await attributor.get_or_create_agent("claude_code", 4321)
    assert counting.writes[writes_after_first:] == ["UPDATE", "COMMIT"]
    cur = await db.execute("SELECT pid FROM agents WHERE id = ?", (first,))
    assert (await cur.fetchone())["pid"] == 4321


@pytest.mark.asyncio
async def test_the_cache_does_not_carry_an_id_to_a_different_database(db, tmp_path, monkeypatch):
    attributor = Attributor()
    first = await attributor.get_or_create_agent("claude_code", 1)
    await database.close_db()
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "another.db")
    database._db = None
    other = await database.get_db()
    await other.execute("INSERT INTO agents (name, process_name, approved) VALUES ('filler', 'filler', 1)")
    await other.commit()
    second = await attributor.get_or_create_agent("claude_code", 1)
    cur = await other.execute("SELECT name FROM agents WHERE id = ?", (second,))
    assert (await cur.fetchone())["name"] == "claude_code", "the id belongs to the database that issued it"


@pytest.mark.asyncio
async def test_a_new_agent_name_is_still_created_and_an_unapproved_one_still_alerts(db):
    attributor = Attributor()
    agent_id = await attributor.get_or_create_agent("brand_new_agent", 5)
    cur = await db.execute("SELECT approved FROM agents WHERE id = ?", (agent_id,))
    assert (await cur.fetchone())["approved"] == 0
    cur = await db.execute("SELECT COUNT(*) AS c FROM alerts WHERE agent_id = ?", (agent_id,))
    assert (await cur.fetchone())["c"] >= 1


# ------------------------------------------------------------------ dropped events are reported

@pytest.mark.asyncio
async def test_health_reports_what_was_dropped_and_what_was_outside_scope(db):
    import main as main_module

    watch_stats.add_dropped("overload")
    watch_stats.add_dropped("buffer_full")
    watch_stats.add_dropped("overload")
    watch_stats.add_out_of_scope()
    set_file_watcher_tier("etw")
    health = await main_module.health()
    not_recorded = health["file_events_not_recorded"]
    assert not_recorded["dropped_total"] == 3 and not_recorded["dropped_by_kind"] == {"overload": 2, "buffer_full": 1}
    assert not_recorded["outside_scope_not_recorded"] == 1 and not_recorded["since"]
    assert health["file_watcher_tier"] == "etw"


def test_reports_say_what_was_dropped_and_what_was_counted_only():
    import api.export as export_module

    assert report_coverage.not_recorded_lines() == []
    watch_stats.add_dropped("overload")
    watch_stats.add_out_of_scope()
    set_file_watcher_tier("etw")
    lines = report_coverage.not_recorded_lines()
    assert len(lines) == 2 and "1 file changes were not recorded because too many arrived at once" in lines[0]
    assert "1 file events outside the watched folders were seen and not recorded" in lines[1]
    notes = export_module.current_report_notes()
    assert export_module.dropped_changes_note(1) in notes and export_module.outside_scope_note(1) in notes
    set_file_watcher_tier("folders")
    assert len(report_coverage.not_recorded_lines()) == 1, "the outside-scope count is an ETW-tier fact"


def test_the_etw_wording_no_longer_claims_changes_are_recorded_wherever_they_happen():
    import api.export as export_module

    assert "wherever they happen" not in export_module.FILE_SCOPE_NOTE_ETW
    assert "counted, not recorded" in export_module.FILE_SCOPE_NOTE_ETW
    doc = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert "anywhere on this computer" not in doc.split("**ETW tier:**", 1)[1].split("\n", 1)[0]


# ------------------------------------------------------------------ the tier switch

def test_the_tier_switch_reads_the_environment_and_ignores_nonsense(monkeypatch):
    monkeypatch.delenv(file_watcher.FILE_WATCHER_ENV, raising=False)
    assert file_watcher.requested_file_watcher_tier() == "auto"
    for value, expected in (("native", "native"), ("NATIVE", "native"), (" polling ", "polling"), ("etw", "etw"), ("", "auto"), ("kernel", "auto")):
        monkeypatch.setenv(file_watcher.FILE_WATCHER_ENV, value)
        assert file_watcher.requested_file_watcher_tier() == expected, value


@pytest.mark.asyncio
async def test_native_forces_the_native_observer_without_trying_etw(monkeypatch):
    built = {"etw": 0, "native": 0, "polling": 0}

    class FakeETW:
        def __init__(self, attributor, **kw):
            built["etw"] += 1

        def set_callback(self, fn):
            pass

        def start(self):
            return True

    class FakeObserver:
        kind = "native"

        def __init__(self, *a, **kw):
            built[self.kind] += 1

        def schedule(self, *a, **kw):
            return object()

        def start(self):
            pass

    class FakePolling(FakeObserver):
        kind = "polling"

    class FakeCache:
        def __init__(self, attributor):
            pass

        def start(self):
            pass

    monkeypatch.setattr(file_watcher, "ETWFileWatcher", FakeETW)
    monkeypatch.setattr(file_watcher, "Observer", FakeObserver)
    monkeypatch.setattr(file_watcher, "PollingObserver", FakePolling)
    monkeypatch.setattr(file_watcher, "_AgentPidCache", FakeCache)
    monkeypatch.delenv("VLAW_HOST_ROOT", raising=False)

    async def start(value):
        for key in built:
            built[key] = 0
        if value is None:
            monkeypatch.delenv(file_watcher.FILE_WATCHER_ENV, raising=False)
        else:
            monkeypatch.setenv(file_watcher.FILE_WATCHER_ENV, value)
        watcher, _handler = file_watcher.start_file_watcher(None, None, [])
        return type(watcher).__name__, dict(built)

    assert await start(None) == ("FakeETW", {"etw": 1, "native": 0, "polling": 0}), "auto: ETW first"
    assert await start("native") == ("FakeObserver", {"etw": 0, "native": 1, "polling": 0}), "native: ETW is never tried"
    assert await start("polling") == ("FakePolling", {"etw": 0, "native": 0, "polling": 1})


# ------------------------------------------------------------------ installer

def test_the_post_install_launch_runs_as_the_user_who_started_setup_not_elevated():
    iss = (ROOT / "installer" / "vigil-setup.iss").read_text(encoding="utf-8")
    run = re.search(r"^\[Run\]\s*$(.*?)(?=^\[|\Z)", iss, re.S | re.M).group(1)
    entries = [line for line in run.splitlines() if line.strip().startswith("Filename:")]
    assert len(entries) == 1
    assert "postinstall" in entries[0] and "runasoriginaluser" in entries[0] and "runascurrentuser" not in entries[0]


# ------------------------------------------------------------------ the activity predicate stays cheap

def test_the_activity_predicate_is_cheap_for_a_session_made_of_ignored_spawns():
    import json
    import sqlite3

    from core.sessions import activity_event_sql

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT, event_type TEXT, path TEXT, detail TEXT)")
    names = ["conhost.exe", "werfault.exe", "vigil.exe", "vigil-backend.exe"]
    conn.executemany(
        "INSERT INTO events (session_id, event_type, path, detail) VALUES ('s1', 'proc_spawn', ?, ?)",
        [(names[i % 4], json.dumps({"command": names[i % 4], "activity_spawn": 1})) for i in range(60000)],
    )
    started = time.perf_counter()
    result = conn.execute(f"SELECT EXISTS (SELECT 1 FROM events e WHERE e.session_id = 's1' AND {activity_event_sql('e')})").fetchone()[0]
    elapsed = time.perf_counter() - started
    assert result == 0
    assert elapsed < 0.25, f"{elapsed:.2f} s for 60,000 ignored spawns (the base-name LIKE tests ran on every row: 0.4 s)"


@pytest.mark.asyncio
async def test_the_current_session_call_does_not_use_the_shared_writer_connection(db, monkeypatch):
    used = {"shared": 0}
    real_get_db = database.get_db

    async def spying_get_db():
        used["shared"] += 1
        return await real_get_db()

    monkeypatch.setattr(mcp_service, "get_db", spying_get_db)
    await mcp_service._get_current_session({})
    assert used["shared"] == 0


# ------------------------------------------------------------------ sustained load

LOAD_SECONDS = float(os.environ.get("VLAW_LOAD_SECONDS", "30"))
EVENTS_PER_SECOND = 5000


class WriteBatchTimings:
    """Collects the "[TIMING] write_batch took Xs" lines the aggregator logs, and any lock errors."""

    import logging as _logging

    def __init__(self):
        import logging

        self.seconds = []
        self.lock_errors = 0

        class Handler(logging.Handler):
            def emit(handler, record):
                message = record.getMessage()
                match = re.search(r"write_batch took ([0-9.]+)s", message)
                if match:
                    self.seconds.append(float(match.group(1)))
                if "database is locked" in message or (record.exc_info and "database is locked" in str(record.exc_info[1])):
                    self.lock_errors += 1

        self.handler = Handler(level=logging.DEBUG)
        self.logger = logging.getLogger("vlaw")

    def __enter__(self):
        self.previous_level = self.logger.level
        self.logger.setLevel(10)
        self.logger.addHandler(self.handler)
        return self

    def __exit__(self, *exc):
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(self.previous_level)


@pytest.mark.asyncio
async def test_5000_etw_events_a_second_from_a_claude_desktop_like_pid_while_the_aggregator_writes(db, monkeypatch):
    attributor = Attributor()
    monkeypatch.setattr(attributor, "get_agent_for_pid", lambda pid: "claude_code" if pid == 4242 else None)
    aggregator = Aggregator()
    aggregator._writer_task = asyncio.create_task(aggregator.start_writer())
    loop = asyncio.get_running_loop()
    handler = file_watcher.VlawFileHandler(attributor, aggregator, loop, pid_cache=None)
    watcher = etw.ETWFileWatcher(attributor, scope=project_scope())
    watcher.set_callback(handler.handle_etw_event)
    watcher._loop = loop

    sent = {"outside": 0, "inside": 0}
    feeding = threading.Event()
    errors = []

    def feeder():
        """5,000 events a second in 50-event ticks of 10 ms: 49 out of 50 are the app's own cache, crash-report and
        log files (outside every watched place), one is a real write in the watched project."""
        try:
            tick, started, n = 0.01, time.perf_counter(), 0
            while time.perf_counter() - started < LOAD_SECONDS:
                for k in range(EVENTS_PER_SECOND // 100):
                    n += 1
                    if k == 0:
                        watcher._process_event(FakeEvent(rf"\Device\HarddiskVolume3\proj\src\f{n}.py", 4242))
                        sent["inside"] += 1
                    else:
                        folder = (CLAUDE_DESKTOP, SENTRY, NPM_LOG)[k % 3]
                        watcher._process_event(FakeEvent(folder.replace("0a1b2c", f"{n:08x}"), 4242))
                        sent["outside"] += 1
                time.sleep(max(0.0, started + (n // (EVENTS_PER_SECOND // 100) + 1) * tick - time.perf_counter()))
        except Exception as exc:       # noqa: BLE001
            errors.append(exc)
        finally:
            feeding.set()

    session_latencies = []

    async def poll_current_session():
        while not feeding.is_set():
            started = time.perf_counter()
            await mcp_service._get_current_session({})
            session_latencies.append(time.perf_counter() - started)
            await asyncio.sleep(0.5)

    async def flush_often():
        while not feeding.is_set():
            await asyncio.sleep(1.0)
            await aggregator.flush_buffers()

    with WriteBatchTimings() as timings:
        thread = threading.Thread(target=feeder, name="etw-feeder")
        thread.start()
        helpers = [asyncio.create_task(poll_current_session()), asyncio.create_task(flush_often())]
        while not feeding.is_set():
            await asyncio.sleep(0.2)
        thread.join()
        await asyncio.gather(*helpers)
        for _ in range(100):
            if watcher._inflight._value == etw.MAX_INFLIGHT_EVENTS:
                break
            await asyncio.sleep(0.1)
        await aggregator.flush_buffers()
        await aggregator.stop_writer()

    assert not errors, errors
    assert sent["outside"] + sent["inside"] >= EVENTS_PER_SECOND * LOAD_SECONDS * 0.8, "the feeder really delivered the rate"

    # nothing outside every watched place reached the database or the loop; all of it was counted
    assert watch_stats.out_of_scope_total() == sent["outside"]
    cur = await db.execute("SELECT COUNT(*) AS c FROM events WHERE path LIKE '%Claude-Data%' OR path LIKE '%sentry%' OR path LIKE '%npm-cache%'")
    assert (await cur.fetchone())["c"] == 0

    # every in-scope write is either stored or counted as dropped: an evidence tool says when it dropped events
    cur = await db.execute("SELECT COUNT(*) AS c FROM events WHERE event_type = 'file_write'")
    stored = (await cur.fetchone())["c"]
    assert stored + watch_stats.dropped_total() == sent["inside"], (stored, watch_stats.dropped_total(), sent["inside"])

    assert timings.seconds, "the aggregator wrote batches while this ran"
    p95 = sorted(timings.seconds)[max(0, int(len(timings.seconds) * 0.95) - 1)]
    assert p95 < 1.0, f"write_batch p95 {p95:.2f} s over {len(timings.seconds)} batches"
    assert timings.lock_errors == 0
    assert session_latencies and sorted(session_latencies)[int(len(session_latencies) * 0.95) - 1 if len(session_latencies) > 1 else 0] < 1.0
