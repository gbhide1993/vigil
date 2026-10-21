"""A change in an agent's own folder (~/.claude for Claude Code, ~/.codex for Codex) is given to that agent by the
file's location, before the best-guess heuristic is used. Anything else keeps the heuristic. The case that
motivated it: session dd20c0e9 was "Agent: codex" but its only activity was 185 Claude Code checkpoint files
under ~/.claude/file-history, given to the idle codex.exe because it was the first agent the guess found."""

import asyncio
import inspect
import os

import pytest

import watchers.file_watcher as file_watcher
from core.attribution import agent_for_path, attribution_for

HOME = r"C:\Users\dev"


@pytest.fixture(autouse=True)
def _home_and_no_red_lines(monkeypatch):
    real = os.path.expanduser
    monkeypatch.setattr(os.path, "expanduser", lambda p: HOME if p == "~" else real(p))
    monkeypatch.setattr(file_watcher, "CORE_ONLY", True)   # no red-line checks: these tests are about attribution only


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
    """Names by pid, like the real one, and remembers which agents were created."""

    def __init__(self, names):
        self.names = names
        self.created = []

        class sessions:
            @staticmethod
            async def touch(agent_id, resumed=False):
                return "sess"

        self.sessions = sessions

    def get_agent_for_pid(self, pid):
        return self.names.get(pid)

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        self.created.append((name, pid))
        return len(self.created)


def _handler(names):
    attributor = _Attributor(names)
    recorder = _Recorder()
    handler = file_watcher.VlawFileHandler(attributor, recorder, asyncio.new_event_loop(), pid_cache=_Cache(names), use_pid_heuristic=True)
    return handler, attributor, recorder


@pytest.fixture
def no_open_handle_refinement(monkeypatch):
    async def none(candidates, path):
        return None

    monkeypatch.setattr(file_watcher, "_refine_pid_by_open_handle", none)


def test_a_file_history_write_with_codex_and_claude_both_running_goes_to_claude_by_location(no_open_handle_refinement):
    # codex.exe is first in the cache, which is what the heuristic would have picked
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"})
    asyncio.run(handler._handle_polled_event(HOME + r"\.claude/file-history/3f265984/c855fd1c9b67a3c2@v1", "file_write", "create"))
    (event,) = recorder.calls
    assert attributor.created == [("claude_code", 20)]
    assert event["pid"] == 20 and event["event_source"] == "path" and event["attribution_confidence"] == "medium"
    assert event["agent_id"] == 1 and event["change"] == "create"


def test_a_write_under_dot_codex_goes_to_codex(no_open_handle_refinement):
    handler, attributor, recorder = _handler({20: "claude_code", 10: "codex"})
    asyncio.run(handler._handle_polled_event(HOME + "/.codex/sessions/2026/rollout.jsonl", "file_write", "write"))
    (event,) = recorder.calls
    assert attributor.created == [("codex", 10)] and event["event_source"] == "path"


def test_a_normal_project_path_keeps_the_heuristic(no_open_handle_refinement):
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"})
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    (event,) = recorder.calls
    assert event["event_source"] == "realtime_heuristic" and event["attribution_confidence"] == "low"
    assert attributor.created == [("codex", 10)], "the first agent it finds, as before"


def test_an_agent_folder_whose_agent_is_not_running_keeps_the_heuristic(no_open_handle_refinement):
    handler, attributor, recorder = _handler({10: "codex"})
    asyncio.run(handler._handle_polled_event(HOME + "/.claude/file-history/x/y@v1", "file_write", "create"))
    (event,) = recorder.calls
    assert event["event_source"] == "realtime_heuristic", "no claude process to name: nothing is invented"


def test_the_polling_tier_uses_the_location_too():
    attributor, recorder = _Attributor({20: "claude_code", 10: "codex"}), _Recorder()
    handler = file_watcher.VlawFileHandler(attributor, recorder, asyncio.new_event_loop(), pid_cache=_Cache({10: "codex", 20: "claude_code"}), use_pid_heuristic=False)
    asyncio.run(handler._handle_polled_event(HOME + "/.claude/file-history/x/y@v1", "file_write", "write"))
    assert recorder.calls[0]["event_source"] == "path" and recorder.calls[0]["pid"] == 20


def test_agent_for_path_is_case_insensitive_takes_both_slashes_and_only_these_two_folders():
    assert agent_for_path(r"C:\Users\dev\.claude\file-history\a") == "claude_code"
    assert agent_for_path("c:/users/DEV/.CLAUDE/projects/x.jsonl") == "claude_code"
    assert agent_for_path(r"C:\Users\dev/.claude/file-history/a") == "claude_code"
    assert agent_for_path(r"C:\Users\dev\.Codex\config.toml") == "codex"
    assert agent_for_path(r"C:\Users\dev\.claude") == "claude_code"
    for other in (r"C:\Users\dev\.claude-backup\a", r"C:\Users\dev\.claudex\a", r"C:\Users\dev\.cursor\a", r"C:\Users\dev\.ssh\id_rsa",
                  r"C:\Users\other\.claude\a", r"C:\work\proj\.claude\settings.json", r"C:\Users\dev\proj\.codex\x", "", None):
        assert agent_for_path(other) is None, other


def test_the_label_says_why():
    path = attribution_for("claude_code", "path", "medium")
    assert path["attribution"] == "path" and path["attribution_confidence"] == "medium"
    assert path["attribution_label"] == "attributed to claude_code by file location, confidence medium"
    assert "best guess" not in path["attribution_label"]
    # the other two are as before
    assert attribution_for("claude_code", "etw", "high")["attribution"] == "exact"
    assert attribution_for("claude_code", "realtime_heuristic", "medium")["attribution"] == "best_guess"


def test_rl3_does_not_depend_on_which_agent_a_file_gets():
    """RL3 (a cache write with no active or recent session) is checked after the session of the attributed agent was
    touched, so that agent always has an open session. Changing the agent changes which session, not whether
    RL3 fires. If that order changes, RL3 and attribution become coupled and this must be looked at again."""
    source = inspect.getsource(file_watcher.VlawFileHandler.handle_file_event)
    assert source.index("sessions.touch(agent_id)") < source.index("self._check_red_lines(")
