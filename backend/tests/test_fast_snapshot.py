"""The 1 s Toolhelp snapshot (watchers/fast_snapshot.py) and ProcessWatcher.fast_tick. See conftest.py for why
VLAW_DATA_DIR is set there."""

import asyncio
import os
import sys

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


def _watcher(monkeypatch, snapshots):
    watcher = ProcessWatcher(attributor=object(), aggregator=None)
    seq = iter(snapshots)
    monkeypatch.setattr(fast_snapshot, "snapshot", lambda: next(seq))
    scans = []

    async def fake_scan():
        scans.append(1)

    monkeypatch.setattr(watcher, "_scan_and_record", fake_scan)
    mass_delete.detector.reset()
    return watcher, scans


BASE = {1: {"name": "explorer.exe", "ppid": 0}, 10: {"name": "claude.exe", "ppid": 1}, 11: {"name": "powershell.exe", "ppid": 10}}


@pytest.mark.asyncio
async def test_a_new_delete_tool_under_an_agent_is_noted_and_asks_for_the_detailed_scan(monkeypatch):
    after = {**BASE, 12: {"name": "bash.exe", "ppid": 11}, 13: {"name": "rm.exe", "ppid": 12}, 14: {"name": "notepad.exe", "ppid": 1}}
    watcher, scans = _watcher(monkeypatch, [BASE, after])
    await watcher.fast_tick()                       # the baseline: nothing is new
    assert watcher.fast_new_agent_children == 0 and scans == []
    await watcher.fast_tick()
    await asyncio.sleep(0)
    assert watcher.fast_new_agent_children == 2, "bash and rm are under claude; notepad is not"
    assert scans == [1], "one detailed scan is asked for"
    spawns = [s for s in mass_delete.detector._spawns]
    assert [s[2] for s in spawns] == ["rm.exe"] and spawns[0][3] == "claude_code"


@pytest.mark.asyncio
async def test_a_process_outside_every_agent_asks_for_nothing(monkeypatch):
    after = {**BASE, 20: {"name": "notepad.exe", "ppid": 1}}
    watcher, scans = _watcher(monkeypatch, [BASE, after])
    await watcher.fast_tick()
    await watcher.fast_tick()
    await asyncio.sleep(0)
    assert scans == [] and watcher.fast_new_agent_children == 0


@pytest.mark.asyncio
async def test_detailed_scans_asked_for_are_rate_limited(monkeypatch):
    s1 = {**BASE, 12: {"name": "bash.exe", "ppid": 11}}
    s2 = {**s1, 13: {"name": "bash.exe", "ppid": 11}}
    watcher, scans = _watcher(monkeypatch, [BASE, s1, s2])
    for _ in range(3):
        await watcher.fast_tick()
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    assert scans == [1], "the second request, a second later, is skipped"


@pytest.mark.asyncio
async def test_a_failing_snapshot_never_raises(monkeypatch):
    watcher = ProcessWatcher(attributor=object(), aggregator=None)

    def boom():
        raise OSError("no")

    monkeypatch.setattr(fast_snapshot, "snapshot", boom)
    await watcher.fast_tick()
