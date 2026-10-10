"""Second calibration pass: time anomalies need a corroborating signal (else
a report info line), and unknown-destination alerts are deduplicated per
session and against the agent's earlier sessions in the last 30 days.
Red-line destination alerts are unaffected. See conftest.py for why
VLAW_DATA_DIR is set there rather than here."""

import uuid
from datetime import timezone

import pytest
import pytest_asyncio

import api.export as export_module
import core.layer2a as layer2a
import db.database as database
from core.layer2a import (
    check_network_destinations, check_time_anomaly, unknown_destination_split, unusual_hour_label,
)
from core.priors import get_prior
from core.red_lines import RedLines

_CREATED_AGENTS: list[int] = []


@pytest_asyncio.fixture
async def test_db():
    database._db = None
    db = await database.get_db()
    layer2a._alerter._last_fired.clear()
    yield db
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


async def _agent(db, label="claude_code_pass2") -> tuple[int, str]:
    name = _uniq(label)
    cur = await db.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name),
    )
    await db.commit()
    _CREATED_AGENTS.append(cur.lastrowid)
    return cur.lastrowid, name


async def _session(db, agent_id, started, resumed=False) -> str:
    sid = _uniq("sess")
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, ?, ?, ?)",
        (sid, agent_id, started, started, 1 if resumed else 0),
    )
    await db.commit()
    return sid


async def _net(db, agent_id, sid, dest, at, times=1):
    for _ in range(times):
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, 'net_connect', ?, ?)",
            (agent_id, sid, dest, at),
        )
    await db.commit()


async def _alert_rows(db, sid, rule_type=None):
    sql = "SELECT * FROM alerts WHERE session_id = ?"
    args = [sid]
    if rule_type:
        sql += " AND rule_type = ?"
        args.append(rule_type)
    cur = await db.execute(sql, args)
    return [dict(r) for r in await cur.fetchall()]


# ============================================================ time anomalies

@pytest.fixture(autouse=True)
def _utc(monkeypatch):
    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)


@pytest.mark.asyncio
async def test_uncorroborated_time_anomaly_is_not_an_alert(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-01 23:40:00")
    assert await check_time_anomaly(sid, agent_id, name, "2026-02-01 23:40:00", get_prior(name), test_db) == []
    assert await _alert_rows(test_db, sid) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("signal", ["credential", "network_alert", "red_line_low", "red_line_medium", "mcp"])
async def test_corroborated_time_anomaly_still_alerts(test_db, signal):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-01 23:40:00")
    if signal == "credential":
        await test_db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'cred_access', '/x/.env')",
            (agent_id, sid),
        )
    else:
        rule_type, severity, reason = {
            "network_alert": ("unknown_destination", "medium", "unknown_destination"),
            "red_line_low": ("red_line", "low", "red_line_unknown_destination"),
            "red_line_medium": ("red_line", "medium", "red_line_env_outside_workspace"),
            "mcp": ("policy", "high", "unapproved_mcp"),
        }[signal]
        await test_db.execute(
            "INSERT INTO alerts (agent_id, severity, title, description, rule_type, session_id, reason) "
            "VALUES (?, ?, 't', 'd', ?, ?, ?)",
            (agent_id, severity, rule_type, sid, reason),
        )
    await test_db.commit()

    ids = await check_time_anomaly(sid, agent_id, name, "2026-02-01 23:40:00", get_prior(name), test_db)
    assert len(ids) == 1
    (alert,) = await _alert_rows(test_db, sid, "time_anomaly")
    # Severity stays capped: only a medium-or-higher red line allows CRITICAL.
    assert alert["severity"] in ("high", "critical")
    if signal != "red_line_medium":
        assert alert["severity"] != "critical"


@pytest.mark.asyncio
async def test_normal_hours_never_alert_even_when_corroborated(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-01 12:00:00")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'cred_access', '/x/.env')",
        (agent_id, sid),
    )
    await test_db.commit()
    assert await check_time_anomaly(sid, agent_id, name, "2026-02-01 12:00:00", get_prior(name), test_db) == []


def test_unusual_hour_label_is_local_time_hh_mm():
    assert unusual_hour_label("2026-02-01 23:40:00", "claude_code") == "23:40"
    assert unusual_hour_label("2026-02-01 12:00:00", "claude_code") is None
    assert unusual_hour_label("2026-02-01 22:00:00", "claude_code") == "22:00"   # upper bound is outside
    assert unusual_hour_label("2026-02-01 06:00:00", "claude_code") is None      # lower bound is inside


@pytest.mark.asyncio
async def test_report_session_gets_unusual_hour_info_only_without_an_alert(test_db):
    agent_id, name = await _agent(test_db)
    quiet = {"id": "s1", "agent_id": agent_id, "agent_name": name, "started_at": "2026-02-01 23:40:00", "resumed": False}
    alerted = {"id": "s2", "agent_id": agent_id, "agent_name": name, "started_at": "2026-02-01 23:40:00", "resumed": False}
    resumed = {"id": "s3", "agent_id": agent_id, "agent_name": name, "started_at": "2026-02-01 23:40:00", "resumed": True}
    daytime = {"id": "s4", "agent_id": agent_id, "agent_name": name, "started_at": "2026-02-01 12:00:00", "resumed": False}

    for session in (quiet, alerted, resumed, daytime):
        await export_module._add_calibration_info(test_db, session, time_alerted={"s2"})

    assert quiet["unusual_hour"] == "23:40"
    assert alerted["unusual_hour"] is None, "already an alert, not duplicated as info"
    assert resumed["unusual_hour"] is None, "a resumed session's start time is when Vigil began watching"
    assert daytime["unusual_hour"] is None


def _pdf_lines(sessions):
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15", "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00", "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC", "event_count": 3, "sessions": sessions, "alerts": [],
            "report_notes": export_module.REPORT_NOTES, "coverage_available": False,
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
    return drawn


def _fake_session(sid, **extra):
    return {
        "id": sid, "started_at": "2026-03-15 23:40:00", "ended_at": "2026-03-15 23:50:00",
        "operator_username": "a", "operator_hostname": "h", "agent_name": "claude_code",
        "event_count_in_period": 3, "no_activity": False, "resumed": False, **extra,
    }


def test_pdf_prints_unusual_hour_and_repeat_destination_info_lines():
    drawn = _pdf_lines([
        _fake_session("aaaaaaaa-1", unusual_hour="23:40", repeat_unknown_destinations=3),
        _fake_session("bbbbbbbb-2", unusual_hour=None, repeat_unknown_destinations=0),
    ])
    hour_lines = [t for t in drawn if "unusual hour" in t]
    dest_lines = [t for t in drawn if "unrecognised destination" in t]
    assert hour_lines == ["(info: started at an unusual hour: 23:40 local)"]
    assert len(dest_lines) == 1 and dest_lines[0].startswith("(info: 3 unrecognised destinations")


# ====================================================== unknown destinations

DEST = "203.0.113.9:443"


@pytest.mark.asyncio
async def test_first_seen_destination_still_alerts(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")

    ids = await check_network_destinations(sid, agent_id, name, get_prior(name), test_db)
    assert len(ids) == 1
    (alert,) = await _alert_rows(test_db, sid, "unknown_destination")
    assert alert["severity"] == "medium" and alert["description"].endswith(DEST)


@pytest.mark.asyncio
async def test_repeat_destination_is_suppressed_and_counted(test_db):
    agent_id, name = await _agent(test_db)
    earlier = await _session(test_db, agent_id, "2026-02-01 10:00:00")
    await _net(test_db, agent_id, earlier, DEST, "2026-02-01 10:00:00")
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")   # 9 days later
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")

    prior = get_prior(name)
    assert await check_network_destinations(sid, agent_id, name, prior, test_db) == []
    new, repeat = await unknown_destination_split(sid, agent_id, prior, test_db)
    assert new == [] and repeat == [DEST]

    info = {"id": sid, "agent_id": agent_id, "agent_name": name, "started_at": "2026-02-10 10:00:00", "resumed": False}
    await export_module._add_calibration_info(test_db, info, time_alerted=set())
    assert info["repeat_unknown_destinations"] == 1


@pytest.mark.asyncio
async def test_destination_last_seen_over_30_days_ago_alerts_again(test_db):
    agent_id, name = await _agent(test_db)
    earlier = await _session(test_db, agent_id, "2026-01-01 10:00:00")
    await _net(test_db, agent_id, earlier, DEST, "2026-01-01 10:00:00")
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")   # 40 days later
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")
    assert len(await check_network_destinations(sid, agent_id, name, get_prior(name), test_db)) == 1


@pytest.mark.asyncio
async def test_resumed_earlier_session_and_other_agents_do_not_suppress(test_db):
    agent_id, name = await _agent(test_db)
    other_id, _ = await _agent(test_db, "cursor_pass2_other")

    resumed_earlier = await _session(test_db, agent_id, "2026-02-01 10:00:00", resumed=True)
    await _net(test_db, agent_id, resumed_earlier, DEST, "2026-02-01 10:00:00")
    other_agent_earlier = await _session(test_db, other_id, "2026-02-02 10:00:00")
    await _net(test_db, other_id, other_agent_earlier, DEST, "2026-02-02 10:00:00")

    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")
    assert len(await check_network_destinations(sid, agent_id, name, get_prior(name), test_db)) == 1


@pytest.mark.asyncio
async def test_later_sessions_do_not_suppress_earlier_ones(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")
    later = await _session(test_db, agent_id, "2026-02-12 10:00:00")
    await _net(test_db, agent_id, later, DEST, "2026-02-12 10:00:00")
    assert len(await check_network_destinations(sid, agent_id, name, get_prior(name), test_db)) == 1


@pytest.mark.asyncio
async def test_at_most_one_alert_per_destination_per_session(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00", times=25)
    await _net(test_db, agent_id, sid, "198.51.100.7:443", "2026-02-10 10:00:01", times=25)

    ids = await check_network_destinations(sid, agent_id, name, get_prior(name), test_db)
    assert len(ids) == 2
    destinations = sorted(a["description"].rsplit(": ", 1)[-1] for a in await _alert_rows(test_db, sid, "unknown_destination"))
    assert destinations == sorted([DEST, "198.51.100.7:443"])


@pytest.mark.asyncio
async def test_known_and_local_destinations_never_count(test_db):
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    for dest in ("api.anthropic.com:443", "localhost:8080", "127.0.0.1"):
        await _net(test_db, agent_id, sid, dest, "2026-02-10 10:00:00")
    assert await unknown_destination_split(sid, agent_id, get_prior(name), test_db) == ([], [])


@pytest.mark.asyncio
async def test_red_line_destination_alert_is_unaffected_by_repeat_suppression(test_db):
    """The red-line unrecognised-destination check keeps firing for a
    destination the policy-style alert would now suppress as a repeat."""
    agent_id, name = await _agent(test_db)
    earlier = await _session(test_db, agent_id, "2026-02-01 10:00:00")
    await _net(test_db, agent_id, earlier, DEST, "2026-02-01 10:00:00")
    sid = await _session(test_db, agent_id, "2026-02-10 10:00:00")
    await _net(test_db, agent_id, sid, DEST, "2026-02-10 10:00:00")

    assert await check_network_destinations(sid, agent_id, name, get_prior(name), test_db) == []   # repeat: no alert

    await RedLines().check_unknown_destination(agent_id, name, DEST, session_id=sid)
    red = await _alert_rows(test_db, sid, "red_line")
    assert len(red) == 1 and red[0]["title"].startswith("RED LINE")


@pytest.mark.asyncio
async def test_red_line_alerts_are_unaffected_by_time_anomaly_rule(test_db):
    """A medium-or-higher red line is itself a corroborating signal, never
    something the time rule removes or caps."""
    agent_id, name = await _agent(test_db)
    sid = await _session(test_db, agent_id, "2026-02-01 23:40:00")
    await RedLines().check_dangerous_command(agent_id, name, "git push --force origin main", "git", session_id=sid)
    (red,) = await _alert_rows(test_db, sid, "red_line")
    assert red["severity"] == "high"

    ids = await check_time_anomaly(sid, agent_id, name, "2026-02-01 23:40:00", get_prior(name), test_db)
    assert len(ids) == 1, "the high red line corroborates the unusual hour"
    (red_after,) = await _alert_rows(test_db, sid, "red_line")
    assert red_after["severity"] == "high"
