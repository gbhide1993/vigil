"""A file write that two or more agents could have made, and that nothing narrows down (no path rule, no open handle),
is recorded as "unattributed" with low confidence, not given to whichever agent was first in the cache. The case that
motivated it: Claude Code's writes were recorded under an idle codex.exe because it came first. See conftest.py for why
VLAW_DATA_DIR is set there rather than here."""

import asyncio
import os

import pytest
import pytest_asyncio

import db.database as database
import watchers.file_watcher as file_watcher
from core.aggregator import Aggregator
from core.attribution import UNATTRIBUTED_AGENT, attribution_for, event_attribution
from core.attributor import Attributor
from core.file_changes import rows_to_changes

HOME = r"C:\Users\dev"
WORDING = "2 agents active, cannot tell which wrote this"


@pytest.fixture(autouse=True)
def _home_and_no_red_lines(monkeypatch):
    real = os.path.expanduser
    monkeypatch.setattr(os.path, "expanduser", lambda p: HOME if p == "~" else real(p))
    monkeypatch.setattr(file_watcher, "CORE_ONLY", True)


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
    def __init__(self, names):
        self.names = names
        self.created = []
        self.unattributed_created = 0

        class sessions:
            touched = []

            @staticmethod
            async def touch(agent_id, resumed=False):
                sessions.touched.append(agent_id)
                return "sess"

        self.sessions = sessions

    def get_agent_for_pid(self, pid):
        return self.names.get(pid)

    def get_behaviour_score_for_pid(self, pid):
        return None

    async def get_or_create_agent(self, name, pid=None, confidence=None):
        self.created.append((name, pid))
        return len(self.created)

    async def get_or_create_unattributed_agent(self):
        self.unattributed_created += 1
        return 99


def _handler(names, use_pid_heuristic=True):
    attributor, recorder = _Attributor(names), _Recorder()
    handler = file_watcher.VlawFileHandler(attributor, recorder, asyncio.new_event_loop(), pid_cache=_Cache(names), use_pid_heuristic=use_pid_heuristic)
    return handler, attributor, recorder


@pytest.fixture
def no_open_handle(monkeypatch):
    async def none(candidates, path):
        return None

    monkeypatch.setattr(file_watcher, "_refine_pid_by_open_handle", none)


# ------------------------------------------------------------------ the choice

@pytest.mark.parametrize("use_pid_heuristic", [True, False])
def test_two_agents_and_no_other_signal_is_unattributed_not_the_first_agent(no_open_handle, use_pid_heuristic):
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"}, use_pid_heuristic)
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    (event,) = recorder.calls
    assert event["agent_id"] == 99 and attributor.unattributed_created == 1
    assert attributor.created == [], "neither running agent was credited"
    assert event["pid"] is None and event["attribution_confidence"] == "low"
    assert event["agents_active"] == 2
    assert event["event_source"] == ("realtime_heuristic" if use_pid_heuristic else "poll"), "how it was observed is unchanged"


def test_three_agents_say_so(no_open_handle):
    handler, _attributor, recorder = _handler({10: "codex", 20: "claude_code", 30: "cursor"})
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    assert recorder.calls[0]["agents_active"] == 3


def test_one_agent_with_several_processes_is_still_that_agent(no_open_handle):
    handler, attributor, recorder = _handler({10: "claude_code", 11: "claude_code"})
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    (event,) = recorder.calls
    assert attributor.created == [("claude_code", 10)] and event["attribution_confidence"] == "medium"
    assert event.get("agents_active") is None and attributor.unattributed_created == 0


def test_an_open_handle_that_names_one_process_still_attributes_to_it(monkeypatch):
    async def names_one(candidates, path):
        return 20

    monkeypatch.setattr(file_watcher, "_refine_pid_by_open_handle", names_one)
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"})
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    (event,) = recorder.calls
    assert attributor.created == [("claude_code", 20)] and event["attribution_confidence"] == "medium"
    assert attributor.unattributed_created == 0


def test_a_path_rule_still_wins_over_the_ambiguity(no_open_handle):
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"})
    asyncio.run(handler._handle_polled_event(HOME + "/.claude/file-history/x/y@v1", "file_write", "create"))
    (event,) = recorder.calls
    assert event["event_source"] == "path" and attributor.created == [("claude_code", 20)] and attributor.unattributed_created == 0


def test_no_agent_running_still_records_nothing(no_open_handle):
    handler, attributor, recorder = _handler({})
    asyncio.run(handler._handle_polled_event(r"C:\work\proj\src\app.py", "file_write", "write"))
    assert recorder.calls == [] and attributor.unattributed_created == 0


def test_etw_attribution_is_untouched():
    handler, attributor, recorder = _handler({10: "codex", 20: "claude_code"})
    asyncio.run(handler.handle_etw_event(20, r"C:\work\proj\src\app.py", "file_write", 1.0, "write"))
    (event,) = recorder.calls
    assert event["event_source"] == "etw" and event["attribution_confidence"] == "high" and attributor.created == [("claude_code", 20)]


# ------------------------------------------------------------------ the wording

def test_the_label_is_the_wording_asked_for_and_never_says_best_guess():
    fields = attribution_for(UNATTRIBUTED_AGENT, "realtime_heuristic", "low", agents_active=2)
    assert fields["attribution"] == "unattributed" and fields["attribution_confidence"] == "low"
    assert fields["attribution_label"] == WORDING
    assert "best guess" not in fields["attribution_label"]
    assert attribution_for(UNATTRIBUTED_AGENT, "poll", "low", agents_active=3)["attribution_label"] == "3 agents active, cannot tell which wrote this"
    # an older row, or one without a count: still true, and still two or more
    assert attribution_for(UNATTRIBUTED_AGENT, "poll", "low")["attribution_label"] == WORDING


def test_other_attributions_are_unchanged():
    assert attribution_for("claude_code", "etw", "high")["attribution_label"] == "by claude_code"
    assert attribution_for("claude_code", "realtime_heuristic", "low")["attribution_label"] == "attributed to claude_code (best guess), confidence low"
    assert attribution_for("claude_code", "path", "medium")["attribution_label"] == "attributed to claude_code by file location, confidence medium"


def test_event_rows_and_report_rows_carry_the_wording():
    row = {"event_type": "file_write", "agent_name": UNATTRIBUTED_AGENT, "event_source": "realtime_heuristic",
           "detail": '{"attribution_confidence": "low", "change": "write", "agents_active": 2}'}
    assert event_attribution(row)["attribution_label"] == WORDING
    (change,) = rows_to_changes(
        [{"path": "C:/p/a.py", "detail": row["detail"], "event_type": "file_write", "event_source": "realtime_heuristic", "created_at": "2026-10-11 06:00:01"}],
        UNATTRIBUTED_AGENT,
    )
    assert change["attribution"] == "unattributed" and change["attribution_label"] == WORDING and change["attribution_confidence"] == "low"


# ------------------------------------------------------------------ what is stored

@pytest.mark.asyncio
async def test_the_count_reaches_the_stored_detail_on_every_write_path():
    aggregator = Aggregator()
    base = {"agent_id": 99, "session_id": "s", "path": r"C:\work\proj\a.py", "event_type": "file_write",
            "attribution_confidence": "low", "pid": None, "change": "write", "agents_active": 2}
    await aggregator.ingest_file_event({**base, "event_source": "realtime_heuristic"})
    assert aggregator.file_event_buffer[0]["detail"]["agents_active"] == 2

    await aggregator.ingest_file_event({**base, "event_source": "poll", "path": r"C:\work\proj\b.py"})
    (bucket,) = aggregator._file_buffer.values()
    assert bucket["agents_active"] == 2

    await aggregator.ingest_file_event({"agent_id": 1, "session_id": "s", "path": r"C:\work\proj\c.py", "event_type": "file_write",
                                        "attribution_confidence": "medium", "pid": 5, "event_source": "realtime_heuristic"})
    assert "agents_active" not in aggregator.file_event_buffer[1]["detail"], "attributed events carry no count"


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "vlaw.db")
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


@pytest.mark.asyncio
async def test_the_unattributed_agent_is_one_approved_row_and_raises_no_alert(db):
    attributor = Attributor()
    first = await attributor.get_or_create_unattributed_agent()
    second = await attributor.get_or_create_unattributed_agent()
    assert first == second
    cur = await db.execute("SELECT name, approved FROM agents WHERE id = ?", (first,))
    row = await cur.fetchone()
    assert row["name"] == UNATTRIBUTED_AGENT and row["approved"] == 1
    cur = await db.execute("SELECT COUNT(*) AS c FROM agents WHERE name = ?", (UNATTRIBUTED_AGENT,))
    assert (await cur.fetchone())["c"] == 1
    cur = await db.execute("SELECT COUNT(*) AS c FROM alerts WHERE agent_id = ?", (first,))
    assert (await cur.fetchone())["c"] == 0, "it is a label for 'cannot tell', not a program, so no unapproved-agent alert"


def test_the_dashboard_words_an_unattributed_event():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "frontend" / "src" / "components"
    for name in ("LiveFeed.jsx", "History.jsx"):
        text = (root / name).read_text(encoding="utf-8")
        assert text.count("attribution === 'unattributed'") >= 3, name
        assert "attribution_label" in text
