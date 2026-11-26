"""The 1 s Toolhelp snapshot (watchers/fast_snapshot.py) and ProcessWatcher.fast_tick. See conftest.py for why
VLAW_DATA_DIR is set there."""

import os
import sys
import time

import pytest

from core import mass_delete
from watchers import fast_snapshot
from watchers.process_watcher import ProcessWatcher


@pytest.mark.skipif(sys.platform != "win32", reason="Toolhelp is Windows only")
def test_the_snapshot_lists_this_process_with_its_parent():
    snap = fast_snapshot.snapshot()
    me = snap[os.getpid()]
    assert me["name"].startswith("python") and me["ppid"] == os.getppid() and len(snap) > 20


@pytest.mark.skipif(sys.platform == "win32", reason="the non-Windows answer")
def test_the_snapshot_is_empty_off_windows():
    assert fast_snapshot.snapshot() == {}


def test_process_details_reads_this_process_and_skips_one_that_is_gone():
    details = fast_snapshot.process_details([os.getpid(), 2_000_000_000])
    assert list(details) == [os.getpid()]
    args, exe, started = details[os.getpid()]
    assert args and exe.lower().endswith(".exe")
    assert 0 < started <= time.time()


BASE = {1: {"name": "explorer.exe", "ppid": 0}, 10: {"name": "claude.exe", "ppid": 1}, 11: {"name": "powershell.exe", "ppid": 10}}


def _watcher(monkeypatch, snapshots, details=None):
    watcher = ProcessWatcher(attributor=object(), aggregator=None)
    watcher._is_first_poll = False
    watcher._known_pids = set(BASE)
    seq = iter(snapshots)
    monkeypatch.setattr(fast_snapshot, "snapshot", lambda: next(seq))
    monkeypatch.setattr(fast_snapshot, "process_details", lambda pids: {p: d for p, d in (details or {}).items() if p in pids})
    written = []

    async def fake_write(current):
        written.append(set(current))

    monkeypatch.setattr(watcher, "_poll_write_phase", fake_write)
    mass_delete.detector.reset()
    return watcher, written


@pytest.mark.asyncio
async def test_a_new_process_under_an_agent_is_read_and_recorded_through_the_scan_path(monkeypatch):
    after = {**BASE, 12: {"name": "bash.exe", "ppid": 11}, 13: {"name": "rm.exe", "ppid": 12}, 14: {"name": "notepad.exe", "ppid": 1}}
    details = {12: (["bash.exe", "-c", "rm -rf x"], "C:/Git/bash.exe", 1_800_000_000), 13: (["rm", "-rf", "x"], "C:/Git/rm.exe", 1_800_000_001)}
    watcher, written = _watcher(monkeypatch, [after], details)
    await watcher.fast_tick()
    assert written == [set(after)], "recorded by the same path the slow scan uses"
    assert watcher._cmdline_snapshot[13] == {"args": ["rm", "-rf", "x"], "exe_path": "C:/Git/rm.exe"}
    assert watcher._pid_snapshot[13]["started"] == 1_800_000_001 and watcher._pid_snapshot[14]["started"] == 0
    assert watcher.fast_new_agent_children == 2, "bash and rm are under claude; notepad is not"
    assert [s[2] for s in mass_delete.detector._spawns] == ["rm.exe"]


@pytest.mark.asyncio
async def test_nothing_new_under_an_agent_writes_nothing_and_still_tracks_the_processes(monkeypatch):
    after = {**BASE, 20: {"name": "notepad.exe", "ppid": 1}}
    watcher, written = _watcher(monkeypatch, [after])
    await watcher.fast_tick()
    assert written == [] and watcher._known_pids == set(after) and 20 in watcher._pid_snapshot


@pytest.mark.asyncio
async def test_a_process_that_exited_before_it_could_be_read_is_still_recorded_by_name(monkeypatch):
    after = {**BASE, 12: {"name": "rm.exe", "ppid": 11}}
    watcher, written = _watcher(monkeypatch, [after], details={})
    await watcher.fast_tick()
    assert written == [set(after)] and 12 not in watcher._cmdline_snapshot


@pytest.mark.asyncio
async def test_before_the_slow_scan_has_set_the_baseline_nothing_is_a_spawn(monkeypatch):
    after = {**BASE, 12: {"name": "bash.exe", "ppid": 11}}
    watcher, written = _watcher(monkeypatch, [after])
    watcher._is_first_poll = True
    await watcher.fast_tick()
    assert written == [] and watcher.fast_new_agent_children == 0


@pytest.mark.asyncio
async def test_the_fast_tick_carries_the_30_s_heartbeat_once_per_30_s(monkeypatch):
    import core.monitoring_coverage as coverage

    ticks = []

    async def fake_tick():
        ticks.append(1)

    monkeypatch.setattr(coverage, "record_coverage_tick", fake_tick)
    watcher, _written = _watcher(monkeypatch, [BASE, BASE, BASE])
    watcher.fast_heartbeat = True
    for _ in range(3):
        await watcher.fast_tick()
    assert ticks == [1]
    watcher._last_heartbeat -= 31
    watcher._is_first_poll = True            # nothing else to do this tick, only the heartbeat
    await watcher.fast_tick()
    assert ticks == [1, 1]


@pytest.mark.asyncio
async def test_the_slow_scan_keeps_the_heartbeat_when_the_fast_path_is_off(monkeypatch):
    import core.monitoring_coverage as coverage

    ticks = []

    async def fake_tick():
        ticks.append(1)

    async def no_scan():
        return None

    monkeypatch.setattr(coverage, "record_coverage_tick", fake_tick)
    watcher = ProcessWatcher(attributor=object(), aggregator=None)
    monkeypatch.setattr(watcher, "_scan_and_record", no_scan)
    await watcher.poll()
    watcher.fast_heartbeat = True
    await watcher.poll()
    assert ticks == [1]


@pytest.mark.asyncio
async def test_a_failing_snapshot_never_raises(monkeypatch):
    watcher = ProcessWatcher(attributor=object(), aggregator=None)
    watcher._is_first_poll = False

    def boom():
        raise OSError("no")

    monkeypatch.setattr(fast_snapshot, "snapshot", boom)
    await watcher.fast_tick()
