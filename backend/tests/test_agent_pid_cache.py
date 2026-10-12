"""Tests for watchers/file_watcher.py's _AgentPidCache._refresh() and the
snapshot-based attribution path it now uses (core/attributor.py's
_walk_parent_chain_from_snapshot).

Context: py-spy on the live backend showed the "vlaw-agent-pid-cache"
thread as the only active thread in 3/3 dumps, inside
_walk_parent_chain's per-level psutil.Process(pid).parent()/create_time()
calls -- one fresh OS process handle opened per parent-chain level, for
every process on the machine, every 30s refresh. That's the sustained
~0.96-core/GIL-starvation source stalling /api/health (3s) and
/api/sessions (16s on first call). _refresh() now builds one
{pid: {"name","ppid"}} snapshot per call (single psutil.process_iter()
pass) and resolves every PID from it -- zero psutil.Process() calls."""

import time

import psutil
import pytest

from core.attributor import KNOWN_AGENTS, Attributor
from watchers.file_watcher import _AgentPidCache


class _FakeProcess:
    """Stands in for psutil.Process in the old, no-snapshot code path --
    .name() and .parent() walk the same synthetic tree a pid_snapshot
    dict would describe, so the two paths can be compared on identical
    data."""

    def __init__(self, pid, tree):
        self._pid = pid
        self._tree = tree

    def name(self):
        return self._tree[self._pid]["name"]

    def parent(self):
        ppid = self._tree[self._pid]["ppid"]
        if not ppid or ppid == self._pid or ppid not in self._tree:
            return None
        return _FakeProcess(ppid, self._tree)


def _make_tree():
    """A small synthetic process tree exercising: a direct name match, a
    match found only by walking up to a parent, a process with no agent
    anywhere in its chain, and a process whose ppid isn't in the
    snapshot at all (simulates a parent that already exited)."""
    return {
        1: {"name": "System", "ppid": 0},
        100: {"name": "cmd.exe", "ppid": 1},
        200: {"name": "claude.exe", "ppid": 1},
        300: {"name": "python.exe", "ppid": 200},  # child of claude.exe
        301: {"name": "conhost.exe", "ppid": 300},  # grandchild
        400: {"name": "notepad.exe", "ppid": 1},  # no agent anywhere
        500: {"name": "orphan.exe", "ppid": 99999},  # ppid missing from tree
    }


@pytest.mark.parametrize("pid", [1, 100, 200, 300, 301, 400, 500])
def test_snapshot_path_matches_old_path(monkeypatch, pid):
    tree = _make_tree()
    attributor = Attributor()

    monkeypatch.setattr(psutil, "Process", lambda p: _FakeProcess(p, tree))
    old_result = attributor._walk_parent_chain(pid, pid_snapshot=None)

    snapshot = {p: {"name": info["name"], "ppid": info["ppid"]} for p, info in tree.items()}
    new_result = attributor._walk_parent_chain(pid, pid_snapshot=snapshot)

    assert old_result == new_result


def test_snapshot_path_resolves_via_parent_walk():
    """python.exe (pid 300) isn't itself a known agent name, but its
    parent (claude.exe, pid 200) is -- confirms the walk actually climbs
    the chain through the snapshot, not just name-matching pid itself."""
    tree = _make_tree()
    snapshot = {p: {"name": info["name"], "ppid": info["ppid"]} for p, info in tree.items()}
    attributor = Attributor()

    assert attributor._walk_parent_chain(300, pid_snapshot=snapshot) == "claude_code"
    assert attributor._walk_parent_chain(301, pid_snapshot=snapshot) == "claude_code"
    assert attributor._walk_parent_chain(400, pid_snapshot=snapshot) is None
    assert attributor._walk_parent_chain(500, pid_snapshot=snapshot) is None


def test_refresh_400_processes_under_200ms_no_psutil_process_construction(monkeypatch):
    """The gate from the P1 perf investigation: one _refresh() call over
    a realistic process count must finish well under 200ms, and must
    never construct a psutil.Process() at all -- confirms the fix
    actually eliminated the per-level OS handle opens, not just made
    them faster."""
    n = 400
    synthetic = {}
    # Every 10th process is a known agent by name; every 11th is a child
    # of the agent two slots before it, to exercise the parent-walk path
    # too, not just direct name matches. The rest are ordinary processes.
    agent_names = [names[0] for names in KNOWN_AGENTS.values()]
    for i in range(n):
        pid = 1000 + i
        if i % 10 == 0:
            name = agent_names[i % len(agent_names)]
            ppid = 1
        elif i % 11 == 0 and i >= 10:
            name = "child_of_agent.exe"
            ppid = 1000 + (i - 1)
        else:
            name = f"ordinary_process_{i}.exe"
            ppid = 1
        synthetic[pid] = {"pid": pid, "name": name, "ppid": ppid}

    class _FakeIterProc:
        def __init__(self, info):
            self.info = info

    def fake_process_iter(attrs=None):
        return (_FakeIterProc(info) for info in synthetic.values())

    def fail_if_constructed(pid):
        raise AssertionError(
            f"psutil.Process({pid}) was constructed -- _refresh() must resolve "
            "attribution entirely from the pid_snapshot, never open a fresh "
            "OS process handle per PID/level"
        )

    monkeypatch.setattr(psutil, "process_iter", fake_process_iter)
    monkeypatch.setattr(psutil, "Process", fail_if_constructed)

    cache = _AgentPidCache(Attributor())

    t0 = time.perf_counter()
    cache._refresh()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert elapsed_ms < 200, f"_refresh() took {elapsed_ms:.1f}ms for {n} processes, budget is 200ms"
    assert len(cache.snapshot()) > 0, "expected at least the direct name-matched agents to resolve"
