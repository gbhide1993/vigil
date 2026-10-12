"""Tests for the alert calibration rules (core/activity_filter.py and its use
in core/layer2a.py, core/layer2b.py, core/red_lines.py's checkpoint tier and
the report). One section per rule. See conftest.py for why VLAW_DATA_DIR is
set there rather than here."""

import json
import uuid
from datetime import timezone

import pytest
import pytest_asyncio

import core.layer2a as layer2a
import core.layer2b as layer2b
import db.database as database
from core.activity_filter import (
    FILE_WRITE_FLOOR, PROCESS_FLOOR, Corroboration, cap_severity, is_generated_path, is_helper_process,
    session_volume_metrics,
)
from core.layer2a import check_hard_thresholds, check_time_anomaly
from core.layer2b import score_session_2b
from core.priors import get_prior
from core.red_lines import RedLines


_CREATED_AGENTS: list[int] = []


@pytest_asyncio.fixture
async def test_db():
    database._db = None
    db = await database.get_db()
    layer2a._alerter._last_fired.clear()
    layer2b._alerter._last_fired.clear()
    yield db
    # The shared test DB is not reset between test files, and the evidence
    # chain tests assert on how many events one seal pass (capped at 500)
    # picks up. These tests insert hundreds of process events, so remove
    # the unsealed events they created instead of leaving them behind.
    if _CREATED_AGENTS:
        marks = ",".join("?" * len(_CREATED_AGENTS))
        await db.execute(
            f"DELETE FROM events WHERE agent_id IN ({marks}) AND id NOT IN (SELECT event_id FROM event_chain)",
            tuple(_CREATED_AGENTS),
        )
        await db.commit()
        _CREATED_AGENTS.clear()
    await database.close_db()


def _uniq(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:8]}"


async def _agent(db, label="claude_code_calib") -> tuple[int, str]:
    name = _uniq(label)
    cur = await db.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name),
    )
    await db.commit()
    _CREATED_AGENTS.append(cur.lastrowid)
    return cur.lastrowid, name


async def _session(db, agent_id, started="2026-01-01 10:00:00", ended="2026-01-01 10:10:00", resumed=False) -> str:
    sid = _uniq("sess")
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, ?, ?, ?)",
        (sid, agent_id, started, ended, 1 if resumed else 0),
    )
    await db.commit()
    return sid


async def _file_writes(db, agent_id, sid, path, count, detail=None):
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count, detail) "
        "VALUES (?, ?, 'file_write', ?, ?, ?)",
        (agent_id, sid, path, count, json.dumps(detail) if detail else None),
    )
    await db.commit()


async def _procs(db, agent_id, sid, command, n, path=None):
    for _ in range(n):
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'proc_spawn', ?, ?)",
            (agent_id, sid, path or command, json.dumps({"command": command})),
        )
    await db.commit()


async def _alerts_for_session(db, sid):
    cur = await db.execute("SELECT * FROM alerts WHERE session_id = ?", (sid,))
    return [dict(r) for r in await cur.fetchall()]


# ----------------------------------------- rule 1: generated paths, helpers

@pytest.mark.parametrize("path", [
    "C:\\proj\\node_modules\\left-pad\\index.js", "/home/u/proj/.venv/lib/python3.12/site.py",
    "C:/proj/src/__pycache__", "C:/proj/dist", "C:/proj/build/out", "C:/proj/.git/objects/ab",
    "C:/Users/u/.cache/pip", "C:/proj/.pytest_cache/v", "C:/Users/u/AppData/Local/Foo/Code Cache/js",
])
def test_generated_and_dependency_paths_are_recognised(path):
    assert is_generated_path(path)


@pytest.mark.parametrize("path", [
    "C:/proj/src/app.py", "C:/proj/distribution/readme.md", "C:/proj/rebuild/x.py", "C:/proj/.github/ci.yml", "",
])
def test_ordinary_paths_are_not_generated(path):
    assert not is_generated_path(path)


def test_helper_process_names():
    for name in ("conhost.exe", "cmd.exe", "bash.exe", "sh.exe", "powershell.exe", "claude.exe", "C:\\x\\Claude.EXE"):
        assert is_helper_process(name), name
    for name in ("python.exe", "node.exe", "git.exe", "curl.exe"):
        assert not is_helper_process(name), name


@pytest.mark.asyncio
async def test_generated_paths_and_helper_processes_are_not_counted(test_db):
    agent_id, _ = await _agent(test_db)
    sid = await _session(test_db, agent_id)

    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 40)
    await _file_writes(test_db, agent_id, sid, "C:/proj/node_modules/pkg", 5000)
    await _file_writes(test_db, agent_id, sid, "C:/proj/.venv/Lib", 3000)
    await _file_writes(test_db, agent_id, sid, "C:/proj/dist", 700)
    # Aggregated row whose per-file list is mostly generated: only the real ones count.
    await _file_writes(
        test_db, agent_id, sid, "C:/proj", 4,
        detail={"paths": ["C:/proj/a.py", "C:/proj/__pycache__/a.pyc", "C:/proj/node_modules/x.js", "C:/proj/b.py"]},
    )
    await _procs(test_db, agent_id, sid, "conhost.exe", 60)
    await _procs(test_db, agent_id, sid, "bash.exe", 60)
    await _procs(test_db, agent_id, sid, "python.exe", 7)
    await _procs(test_db, agent_id, sid, "node.exe", 3, path="node C:/proj/node_modules/.bin/tool")

    m = await session_volume_metrics(test_db, sid, agent_id)
    assert m["file_writes"] == 40 + 2
    assert m["processes"] == 7


# -------------------------------------------------------- rule 2: floors

@pytest.mark.asyncio
async def test_floor_suppresses_small_file_write_sessions(test_db):
    agent_id, name = await _agent(test_db)
    prior = get_prior(name)
    assert prior["file_events_per_session"]["high"] == 150  # old rule would have fired at 151

    below = await _session(test_db, agent_id)
    await _file_writes(test_db, agent_id, below, "C:/proj/src", FILE_WRITE_FLOOR - 1)
    assert await check_hard_thresholds(below, agent_id, name, prior, test_db) == []

    at_floor = await _session(test_db, agent_id)
    await _file_writes(test_db, agent_id, at_floor, "C:/proj/src", FILE_WRITE_FLOOR)
    assert len(await check_hard_thresholds(at_floor, agent_id, name, prior, test_db)) == 1


@pytest.mark.asyncio
async def test_floor_suppresses_small_process_sessions(test_db):
    agent_id, name = await _agent(test_db)
    prior = get_prior(name)
    assert prior["process_spawns_per_session"]["high"] == 40

    below = await _session(test_db, agent_id)
    await _procs(test_db, agent_id, below, "python.exe", PROCESS_FLOOR - 1)
    assert await check_hard_thresholds(below, agent_id, name, prior, test_db) == []

    at_floor = await _session(test_db, agent_id)
    await _procs(test_db, agent_id, at_floor, "python.exe", PROCESS_FLOOR)
    assert len(await check_hard_thresholds(at_floor, agent_id, name, prior, test_db)) == 1


async def _history(db, agent_id, counts, resumed=False):
    for i, c in enumerate(counts):
        sid = await _session(db, agent_id, f"2026-01-01 0{i}:00:00", f"2026-01-01 0{i}:10:00", resumed=resumed)
        await _file_writes(db, agent_id, sid, "C:/proj/src", c)


@pytest.mark.asyncio
async def test_rolling_needs_three_times_the_floored_baseline(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430, 440))  # median 420 -> 3x = 1260

    just_under = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00")
    await _file_writes(test_db, agent_id, just_under, "C:/proj/src", 1200)
    assert await score_session_2b(just_under, agent_id, name, test_db) == []

    over = await _session(test_db, agent_id, "2026-01-03 10:00:00", "2026-01-03 10:10:00")
    await _file_writes(test_db, agent_id, over, "C:/proj/src", 1300)
    assert len(await score_session_2b(over, agent_id, name, test_db)) == 1


@pytest.mark.asyncio
async def test_rolling_uses_floored_baseline_when_history_is_tiny(test_db):
    """A history of 1-2 writes per session must not make 100 writes look
    like a 50x spike: the baseline is floored, and 100 is also below the
    300 absolute floor."""
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (1, 2, 1, 2, 1))
    sid = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00")
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 100)
    assert await score_session_2b(sid, agent_id, name, test_db) == []


@pytest.mark.asyncio
async def test_rolling_needs_five_history_sessions(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430))  # only 4
    sid = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00")
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 5000)
    assert await score_session_2b(sid, agent_id, name, test_db) == []


@pytest.mark.asyncio
async def test_resumed_history_sessions_do_not_count_toward_the_five(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430))
    resumed = await _session(test_db, agent_id, "2026-01-01 08:00:00", "2026-01-01 08:10:00", resumed=True)
    await _file_writes(test_db, agent_id, resumed, "C:/proj/src", 420)
    sid = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00")
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 5000)
    assert await score_session_2b(sid, agent_id, name, test_db) == [], "4 real + 1 resumed is still only 4"


@pytest.mark.asyncio
async def test_resumed_current_session_is_skipped(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430, 440))
    sid = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00", resumed=True)
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 5000)
    assert await score_session_2b(sid, agent_id, name, test_db) == []


# -------------------------------------------------- rule 3: severity caps

def test_cap_severity_pure():
    none = Corroboration()
    assert cap_severity("critical", none) == "medium"
    assert cap_severity("high", none) == "medium"
    assert cap_severity("medium", none) == "medium"
    assert cap_severity("critical", Corroboration(credential=True)) == "high"
    assert cap_severity("critical", Corroboration(network=True)) == "high"
    assert cap_severity("critical", Corroboration(mcp=True)) == "high"
    assert cap_severity("critical", Corroboration(red_line=True)) == "critical"
    assert cap_severity("high", Corroboration(red_line=True)) == "high"


async def _big_session(db, agent_id):
    """Far past the critical thresholds, so the uncapped severity is critical."""
    sid = await _session(db, agent_id)
    await _file_writes(db, agent_id, sid, "C:/proj/src", 5000)
    return sid


@pytest.mark.asyncio
async def test_uncorroborated_volume_alert_is_capped_at_medium(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _big_session(test_db, agent_id)
    assert len(await check_hard_thresholds(sid, agent_id, name, get_prior(name), test_db)) == 1
    (alert,) = await _alerts_for_session(test_db, sid)
    assert alert["severity"] == "medium"


@pytest.mark.asyncio
async def test_credential_access_lifts_cap_to_high_but_not_critical(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _big_session(test_db, agent_id)
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'cred_access', 'C:/Users/u/.aws/credentials')",
        (agent_id, sid),
    )
    await test_db.commit()
    await check_hard_thresholds(sid, agent_id, name, get_prior(name), test_db)
    (alert,) = [a for a in await _alerts_for_session(test_db, sid) if a["reason"] == "volume_anomaly"]
    assert alert["severity"] == "high"


@pytest.mark.asyncio
async def test_red_line_alert_allows_critical(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _big_session(test_db, agent_id)
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, rule_type, session_id, reason) "
        "VALUES (?, 'high', 'RED LINE: x', 'x', 'red_line', ?, 'red_line_ssh_access')",
        (agent_id, sid),
    )
    await test_db.commit()
    await check_hard_thresholds(sid, agent_id, name, get_prior(name), test_db)
    (alert,) = [a for a in await _alerts_for_session(test_db, sid) if a["reason"] == "volume_anomaly"]
    assert alert["severity"] == "critical"
    assert "red line" in alert["description"]


@pytest.mark.asyncio
async def test_time_anomaly_is_capped_unless_corroborated(test_db, monkeypatch):
    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)
    agent_id, name = await _agent(test_db)
    prior = get_prior(name)

    plain = await _session(test_db, agent_id, "2026-01-01 22:30:00", "2026-01-01 22:40:00")
    assert await check_time_anomaly(plain, agent_id, name, "2026-01-01 22:30:00", prior, test_db) == []

    corroborated = await _session(test_db, agent_id, "2026-01-02 22:30:00", "2026-01-02 22:40:00")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'cred_access', '/x/.env')",
        (agent_id, corroborated),
    )
    await test_db.commit()
    (aid,) = await check_time_anomaly(corroborated, agent_id, name, "2026-01-02 22:30:00", prior, test_db)
    cur = await test_db.execute("SELECT severity FROM alerts WHERE id = ?", (aid,))
    # Base severity "critical" (a 22h gap since the previous session) capped
    # to HIGH: credential access corroborates, but only a red line allows CRITICAL.
    assert (await cur.fetchone())["severity"] == "high"


# ------------------------------------------------ rule 4: duration dropped

@pytest.mark.asyncio
async def test_duration_alone_never_alerts(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430, 440))  # ten-minute sessions
    sid = await _session(test_db, agent_id, "2026-01-02 00:00:00", "2026-01-04 00:00:00")  # two days long
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 10)  # almost no activity
    assert await score_session_2b(sid, agent_id, name, test_db) == []
    assert not any("duration" in (a["title"] + a["description"]).lower() for a in await _alerts_for_session(test_db, sid))


# ------------------------------------------------------------ rule 5: merge

@pytest.mark.asyncio
async def test_volume_findings_merge_into_one_alert_per_session(test_db):
    agent_id, name = await _agent(test_db)
    await _history(test_db, agent_id, (400, 410, 420, 430, 440))

    sid = await _session(test_db, agent_id, "2026-01-02 10:00:00", "2026-01-02 10:10:00")
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 3000)
    await _procs(test_db, agent_id, sid, "python.exe", 300)

    first = await check_hard_thresholds(sid, agent_id, name, get_prior(name), test_db)   # Layer 2a: files + processes
    second = await score_session_2b(sid, agent_id, name, test_db)                         # Layer 2b: files again
    assert len(first) == 1 and len(second) == 1 and first == second, "2b must fold into 2a's alert"

    volume = [a for a in await _alerts_for_session(test_db, sid) if a["reason"] == "volume_anomaly"]
    assert len(volume) == 1
    assert volume[0]["title"] == "Unusual activity volume"
    description = volume[0]["description"]
    assert "file writes" in description and "processes" in description
    assert "typical" in description and "recent median" in description, "both layers' contributions are listed"
    assert not [a for a in await _alerts_for_session(test_db, sid) if a["rule_type"] in ("volumetric_threshold", "rolling_anomaly")]


# ------------------------------------------- rule 6: checkpoint alerts gone

CHECKPOINT_PATH = "C:\\Users\\u/.claude/file-history/abc123/snapshot@v1"


@pytest.mark.asyncio
async def test_checkpoint_write_during_active_session_creates_no_alert(test_db):
    agent_id, name = await _agent(test_db)
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, NULL)",
        (_uniq("sess"), agent_id),
    )
    await test_db.commit()

    before = (await (await test_db.execute("SELECT COUNT(*) c FROM alerts WHERE agent_id = ?", (agent_id,))).fetchone())["c"]
    await RedLines().check_claude_cache_write(agent_id, name, CHECKPOINT_PATH, test_db)
    after = (await (await test_db.execute("SELECT COUNT(*) c FROM alerts WHERE agent_id = ?", (agent_id,))).fetchone())["c"]
    assert after == before == 0


@pytest.mark.asyncio
async def test_cache_write_with_no_session_is_still_a_red_line(test_db):
    """The anomalous tier is untouched: still high, still a red line."""
    agent_id, name = await _agent(test_db)  # no sessions at all
    await RedLines().check_claude_cache_write(agent_id, name, CHECKPOINT_PATH, test_db)
    cur = await test_db.execute("SELECT severity, rule_type FROM alerts WHERE agent_id = ?", (agent_id,))
    rows = [dict(r) for r in await cur.fetchall()]
    assert rows == [{"severity": "high", "rule_type": "red_line"}]


@pytest.mark.asyncio
async def test_report_counts_checkpoint_writes_per_session(test_db):
    import api.export as export_module

    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id)
    other = await _session(test_db, agent_id)
    await _file_writes(test_db, agent_id, sid, CHECKPOINT_PATH, 3)
    await _file_writes(test_db, agent_id, sid, "C:/Users/u/.claude/file-history/def/s@v2", 2)
    await _file_writes(test_db, agent_id, other, "C:/proj/src", 9)

    counts = await export_module._checkpoint_counts_by_session(test_db, "2000-01-01 00:00:00", "2999-01-01 00:00:00")
    assert counts.get(sid) == 5
    assert other not in counts


def test_pdf_prints_one_info_line_per_session_with_checkpoints():
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    import api.export as export_module

    def session(sid, writes):
        return {
            "id": sid, "started_at": "2026-03-15 08:00:00", "ended_at": "2026-03-15 09:00:00",
            "operator_username": "a", "operator_hostname": "h", "agent_name": "claude_code",
            "event_count_in_period": 5, "no_activity": False, "resumed": False, "checkpoint_writes": writes,
        }

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15", "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00", "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC", "event_count": 10, "sessions": [session("aaaaaaaa-1", 7), session("bbbbbbbb-2", 0)],
            "alerts": [], "report_notes": export_module.REPORT_NOTES, "coverage_available": False,
            "tracking_started_at": None, "active_seconds": 0, "period_seconds_measured": 0,
            "gaps": [], "short_gap_count": 0, "short_gap_seconds": 0,
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

    info = [t for t in drawn if "checkpoint write" in t]
    assert len(info) == 1
    assert "7 checkpoint writes" in info[0] and "normal /rewind activity" in info[0]


# ------------------------------------------ rule 7: red lines unaffected

@pytest.mark.asyncio
async def test_red_line_alert_is_not_capped_floored_or_merged(test_db):
    """A dangerous-command red line in a tiny, uncorroborated session keeps
    its own severity and rule_type: none of the calibration applies to it."""
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id)
    await _file_writes(test_db, agent_id, sid, "C:/proj/src", 1)  # far below every floor

    await RedLines().check_dangerous_command(agent_id, name, "git push --force origin main", "git", session_id=sid)
    cur = await test_db.execute("SELECT severity, rule_type, title FROM alerts WHERE agent_id = ?", (agent_id,))
    rows = [dict(r) for r in await cur.fetchall()]
    assert len(rows) == 1
    assert rows[0]["severity"] == "high" and rows[0]["rule_type"] == "red_line"
    assert rows[0]["title"].startswith("RED LINE")
