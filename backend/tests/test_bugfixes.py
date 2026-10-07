"""Regression tests for the bugfixes applied to:
  - core/layer2a.py       (network host matching, time-anomaly boundary)
  - core/sessions.py      (alert_count timing, orphaned-session recovery)
  - core/cross_agent.py   (persisted cross-agent alert dedup)
  - license/license_service.py (expiry-aware valid/reason, corrupt marker)
  - api/export.py         (bad ?date= returns 400 instead of 500)
  - main.py               (unprefixed routers shadowing the SPA fallback
                            in a frozen build -- /alerts, /agents,
                            /incidents)

See conftest.py for why VLAW_DATA_DIR is set there rather than here --
this module (and anything it imports) must only ever touch that isolated
temp DB, never the real dev DB in backend/data/."""

import asyncio
import json
import sys
import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
import pytest_asyncio

import db.database as database
from db.database import get_db

from core.priors import get_prior
from core.layer2a import check_network_destinations, check_time_anomaly
import core.layer2a as layer2a
from core.sessions import SessionManager
from core.baseline import Baseline
from core.cross_agent import check_cross_agent_file_conflict
import core.cross_agent as cross_agent
import license.license_service as license_service
import core.aggregator as aggregator_module
from core.aggregator import Aggregator, ConnectionWedgedError


# ---------------------------------------------------------------- fixtures

@pytest_asyncio.fixture
async def test_db():
    """Fresh aiosqlite connection per test, bound to that test's own event
    loop (pytest-asyncio gives each test function its own loop by
    default) -- resetting the module-global singleton avoids reusing a
    connection created under a different, now-closed loop. The underlying
    DB *file* (VLAW_DATA_DIR, set in conftest.py) persists across tests in
    the same run; tests use unique agent names/session ids/paths so they
    don't interfere with each other.

    Explicitly closes the connection on teardown -- aiosqlite.Connection
    is itself a non-daemon background Thread (confirmed during today's
    write-wedge work), so leaving this connection open just lets it get
    silently overwritten by the next test's database._db = None without
    ever stopping its thread. With ~13 DB-touching tests in this file,
    that leaked one non-daemon thread per test -- harmless to the test
    results themselves (all 35 still pass), but it means the pytest
    process never exits on its own afterward, since Python won't exit
    while any non-daemon thread is still alive. That's invisible
    locally if nothing ever waits on the process exiting, but it's
    exactly what hung CI: the regression-suite step kept running 40+
    minutes after pytest had already printed "35 passed" and finished,
    because the parent `python -m pytest` process itself never returned."""
    database._db = None
    db = await database.get_db()
    yield db
    await database.close_db()


async def _make_agent(db, name: str) -> int:
    cur = await db.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)",
        (name, name),
    )
    await db.commit()
    return cur.lastrowid


def _uniq(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:8]}"


# ------------------------------------------------------- 1. network hosts

@pytest.mark.asyncio
async def test_network_destination_host_matching(test_db):
    layer2a._alerter._last_fired.clear()

    agent_name = _uniq("claude_code_nettest")
    agent_id = await _make_agent(test_db, agent_name)
    prior = get_prior(agent_name)

    should_fire = ["evilgithub.com", "notlocalhost", "127.0.0.1.evil.com"]
    should_not_fire = ["github.com", "api.github.com", "localhost", "127.0.0.1:8000"]

    for dest in should_fire + should_not_fire:
        session_id = _uniq("sess")
        await test_db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'net_connect', ?)",
            (agent_id, session_id, dest),
        )
        await test_db.commit()

        fired = await check_network_destinations(session_id, agent_id, agent_name, prior, test_db)
        if dest in should_fire:
            assert len(fired) == 1, f"expected {dest!r} to fire an alert, it did not"
        else:
            assert fired == [], f"expected {dest!r} NOT to fire an alert, it did"


# ---------------------------------------------------------- 2. time anomaly

@pytest.mark.asyncio
async def test_time_anomaly_boundary(test_db, monkeypatch):
    layer2a._alerter._last_fired.clear()
    # Pin the local timezone to UTC so this test exercises only the hour
    # boundary logic, independent of whatever timezone the machine running
    # it is in.
    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)

    agent_name = _uniq("claude_code_timetest")
    agent_id = await _make_agent(test_db, agent_name)
    prior = get_prior(agent_name)
    assert prior["normal_hours"] == [6, 22]

    fires = await check_time_anomaly(
        _uniq("sess"), agent_id, agent_name, "2026-01-01 22:30:00", prior, test_db,
    )
    assert len(fires) == 1, "22:30 (hour == normal_hours upper bound) should fire"

    no_fire = await check_time_anomaly(
        _uniq("sess"), agent_id, agent_name, "2026-01-01 21:59:00", prior, test_db,
    )
    assert no_fire == [], "21:59 (still inside normal hours) should not fire"


@pytest.mark.asyncio
async def test_time_anomaly_respects_local_timezone(test_db, monkeypatch):
    """The actual bug: a session at 05:34 UTC is 11:04 AM in Pune
    (UTC+5:30), a normal working hour, and must not fire. A session at
    22:00 UTC is 03:30 AM in Pune, outside normal hours, and must fire
    with the local time in its title. A UTC-pinned run must behave exactly
    as before (unchanged at this specific boundary)."""
    layer2a._alerter._last_fired.clear()
    kolkata = timezone(timedelta(hours=5, minutes=30))

    agent_name = _uniq("claude_code_tztest")
    agent_id = await _make_agent(test_db, agent_name)
    prior = get_prior(agent_name)
    assert prior["normal_hours"] == [6, 22]

    monkeypatch.setattr(layer2a, "_local_tz", lambda: kolkata)

    no_fire = await check_time_anomaly(
        _uniq("sess"), agent_id, agent_name, "2026-01-01 05:34:00", prior, test_db,
    )
    assert no_fire == [], "05:34 UTC is 11:04 AM in Asia/Kolkata, inside normal hours"

    fires = await check_time_anomaly(
        _uniq("sess"), agent_id, agent_name, "2026-01-01 22:00:00", prior, test_db,
    )
    assert len(fires) == 1, "22:00 UTC is 03:30 AM in Asia/Kolkata, outside normal hours"

    alert = await test_db.execute(
        "SELECT title FROM alerts WHERE id = ?", (fires[0],)
    )
    title = (await alert.fetchone())["title"]
    assert "3:30 AM" in title, f"expected local time 3:30 AM in title, got: {title!r}"

    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)

    fires_utc = await check_time_anomaly(
        _uniq("sess"), agent_id, agent_name, "2026-01-01 22:30:00", prior, test_db,
    )
    assert len(fires_utc) == 1, "with tz pinned to UTC, 22:30 behaves exactly as before"


# --------------------------------------------------------- 3. session close

class _NoopBaseline:
    async def update_from_session(self, session_id: str) -> None:
        pass


@pytest.mark.asyncio
async def test_close_idle_sessions_alert_count_and_summary(test_db, monkeypatch):
    layer2a._alerter._last_fired.clear()
    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)

    agent_name = _uniq("claude_code_closetest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")

    # started_at at hour 22 -- guaranteed to trip check_time_anomaly (see
    # test_time_anomaly_boundary above), giving this session at least one
    # Layer 2a alert to count and summarize.
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, NULL)",
        (session_id, agent_id, "2026-01-01 22:30:00"),
    )
    # Some real activity so digest.generate_summary's "quiet session" early
    # return doesn't swallow the alert-count sentence.
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count) VALUES (?, ?, 'file_write', ?, 3)",
        (agent_id, session_id, "/tmp/whatever.py"),
    )
    await test_db.commit()

    sm = SessionManager()
    sm._active[agent_id] = {
        "session_id": session_id,
        "last_activity": datetime.now(timezone.utc) - timedelta(seconds=400),
    }

    closed = await sm.close_idle_sessions(_NoopBaseline())
    assert session_id in closed

    cur = await test_db.execute("SELECT alert_count, summary, ended_at FROM sessions WHERE id = ?", (session_id,))
    row = await cur.fetchone()
    assert row["ended_at"] is not None
    assert row["alert_count"] >= 1
    assert "alert" in row["summary"].lower()


# ----------------------------------------------- 4. orphaned session recovery

@pytest.mark.asyncio
async def test_recover_orphaned_sessions(test_db):
    agent_name = _uniq("claude_code_orphantest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")

    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, NULL)",
        (session_id, agent_id),
    )
    await test_db.commit()

    sm = SessionManager()
    count = await sm.recover_orphaned_sessions(_NoopBaseline())
    assert count >= 1

    cur = await test_db.execute("SELECT ended_at, summary FROM sessions WHERE id = ?", (session_id,))
    row = await cur.fetchone()
    assert row["ended_at"] is not None
    assert row["summary"] is not None


@pytest.mark.asyncio
async def test_recover_orphaned_sessions_uses_last_event_time(test_db):
    agent_name = _uniq("claude_code_lasteventtest")
    agent_id = await _make_agent(test_db, agent_name)

    # Session with events at T1 < T2 -- ended_at should land on T2 (the
    # last activity), not "now".
    session_with_events = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, '2026-01-01 10:00:00', NULL)",
        (session_with_events, agent_id),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, 'file_write', ?, ?)",
        (agent_id, session_with_events, "/tmp/a.py", "2026-01-01 10:05:00"),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, 'file_write', ?, ?)",
        (agent_id, session_with_events, "/tmp/b.py", "2026-01-01 10:15:00"),
    )

    # Session with no events at all -- ended_at should fall back to started_at.
    session_no_events = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, '2026-01-01 11:00:00', NULL)",
        (session_no_events, agent_id),
    )
    await test_db.commit()

    sm = SessionManager()
    await sm.recover_orphaned_sessions(_NoopBaseline())

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (session_with_events,))
    assert (await cur.fetchone())["ended_at"] == "2026-01-01 10:15:00"

    cur = await test_db.execute("SELECT ended_at, started_at FROM sessions WHERE id = ?", (session_no_events,))
    row = await cur.fetchone()
    assert row["ended_at"] == row["started_at"] == "2026-01-01 11:00:00"


@pytest.mark.asyncio
async def test_recover_orphaned_sessions_bad_row_does_not_abort(test_db, monkeypatch):
    agent_name = _uniq("claude_code_badrowtest")
    agent_id = await _make_agent(test_db, agent_name)

    bad_session = _uniq("sess")
    good_session = _uniq("sess")
    for sid in (bad_session, good_session):
        await test_db.execute(
            "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, NULL)",
            (sid, agent_id),
        )
    await test_db.commit()

    sm = SessionManager()
    real_roll_up = sm._roll_up_session_stats

    async def _flaky_roll_up(db, session_id, agent_id):
        if session_id == bad_session:
            raise RuntimeError("simulated failure for bad_session")
        return await real_roll_up(db, session_id, agent_id)

    monkeypatch.setattr(sm, "_roll_up_session_stats", _flaky_roll_up)

    count = await sm.recover_orphaned_sessions(_NoopBaseline())
    assert count == 1  # only good_session

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (good_session,))
    assert (await cur.fetchone())["ended_at"] is not None

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (bad_session,))
    assert (await cur.fetchone())["ended_at"] is None  # left for next startup


@pytest.mark.asyncio
async def test_recover_orphaned_sessions_scores(test_db, monkeypatch):
    layer2a._alerter._last_fired.clear()
    monkeypatch.setattr(layer2a, "_local_tz", lambda: timezone.utc)

    agent_name = _uniq("claude_code_recoverscoretest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")

    # hour 22 -- guaranteed to trip check_time_anomaly (see
    # test_time_anomaly_boundary), giving this recovered session an alert.
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, NULL)",
        (session_id, agent_id, "2026-01-01 22:30:00"),
    )
    await test_db.commit()

    sm = SessionManager()
    count = await sm.recover_orphaned_sessions(_NoopBaseline())
    assert count >= 1

    cur = await test_db.execute("SELECT alert_count FROM sessions WHERE id = ?", (session_id,))
    assert (await cur.fetchone())["alert_count"] >= 1


# --------------------------------------------------------- 5. cross-agent

@pytest.mark.asyncio
async def test_cross_agent_file_conflict_dedup(test_db):
    cross_agent._alerter._last_fired.clear()

    agent_a = await _make_agent(test_db, _uniq("claude_code_crossA"))
    agent_b = await _make_agent(test_db, _uniq("cursor_crossB"))
    path = f"/tmp/shared_{uuid.uuid4().hex[:8]}.py"

    for agent_id in (agent_a, agent_b):
        await test_db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'file_write', ?, ?)",
            (agent_id, _uniq("sess"), path, json.dumps({"paths": [path]})),
        )
    await test_db.commit()

    first = await check_cross_agent_file_conflict(test_db)
    assert len(first) == 1

    # Clear the in-memory dedup so the second call's empty result can only
    # be explained by the new DB-persisted _already_alerted() check, not
    # by Alerter._last_fired still remembering the first call.
    cross_agent._alerter._last_fired.clear()

    second = await check_cross_agent_file_conflict(test_db)
    assert second == []


@pytest.mark.asyncio
async def test_cross_agent_dedup_exact_path(test_db):
    """An alert already on record for the LONGER of two paths (one a
    literal prefix of the other) must not suppress a later, genuinely
    different conflict on the shorter one -- instr(title, path) would
    find the shorter path as a plain substring of the longer path's own
    title text and wrongly treat it as already-alerted."""
    cross_agent._alerter._last_fired.clear()

    agent_a = await _make_agent(test_db, _uniq("claude_code_crossA"))
    agent_b = await _make_agent(test_db, _uniq("cursor_crossB"))

    short_path = f"/x/config_{uuid.uuid4().hex[:8]}"
    long_path = short_path + ".bak"

    for agent_id in (agent_a, agent_b):
        await test_db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'file_write', ?, ?)",
            (agent_id, _uniq("sess"), long_path, json.dumps({"paths": [long_path]})),
        )
    await test_db.commit()
    first = await check_cross_agent_file_conflict(test_db)
    assert len(first) == 1

    cross_agent._alerter._last_fired.clear()

    for agent_id in (agent_a, agent_b):
        await test_db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'file_write', ?, ?)",
            (agent_id, _uniq("sess"), short_path, json.dumps({"paths": [short_path]})),
        )
    await test_db.commit()

    second = await check_cross_agent_file_conflict(test_db)
    assert len(second) == 1, "conflict on the shorter path must not be suppressed by the longer path's existing alert"


@pytest.mark.asyncio
async def test_network_destination_dedup_exact_host(test_db):
    """Same class of bug, layer2a's side: an alert already on record for a
    LONGER host must not suppress a later conflict on a SHORTER host that
    happens to be its literal prefix."""
    layer2a._alerter._last_fired.clear()

    agent_name = _uniq("claude_code_hostdeduptest")
    agent_id = await _make_agent(test_db, agent_name)
    prior = get_prior(agent_name)

    long_host = f"api-{uuid.uuid4().hex[:8]}.example.com.evil.net"
    short_host = long_host.removesuffix(".evil.net")

    session_a = _uniq("sess")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'net_connect', ?)",
        (agent_id, session_a, long_host),
    )
    await test_db.commit()
    first = await check_network_destinations(session_a, agent_id, agent_name, prior, test_db)
    assert len(first) == 1

    session_b = _uniq("sess")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'net_connect', ?)",
        (agent_id, session_b, short_host),
    )
    await test_db.commit()
    second = await check_network_destinations(session_b, agent_id, agent_name, prior, test_db)
    assert len(second) == 1, "the shorter host must not be suppressed by the longer host's existing alert"


# ------------------------------------------------------------- 6. license

def test_license_expired_trial_marker_is_invalid(tmp_path, monkeypatch):
    monkeypatch.setattr(license_service, "LICENSE_FILE", tmp_path / "no-such-file.vlaw-license")
    svc = license_service.LicenseService()

    old_start = datetime.now(timezone.utc) - timedelta(days=license_service.TRIAL_DAYS + 1)
    svc._trial_marker_path.parent.mkdir(parents=True, exist_ok=True)
    svc._trial_marker_path.write_text(old_start.isoformat())

    status = svc.get_status()
    assert status.valid is False


def test_license_corrupt_trial_marker_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(license_service, "LICENSE_FILE", tmp_path / "no-such-file.vlaw-license")
    svc = license_service.LicenseService()

    svc._trial_marker_path.parent.mkdir(parents=True, exist_ok=True)
    svc._trial_marker_path.write_text("not-a-valid-timestamp")

    status = svc.get_status()  # must not raise
    assert status.plan == "trial"
    assert status.valid is True  # marker was corrupt -> restarted fresh


def test_license_malformed_file_falls_back_to_trial(tmp_path, monkeypatch):
    license_file = tmp_path / ".vlaw-license"
    license_file.write_text("not valid json{{{")
    monkeypatch.setattr(license_service, "LICENSE_FILE", license_file)
    svc = license_service.LicenseService()

    status = svc.get_status()
    assert status.plan == "trial"
    assert status.agent_limit == license_service.TRIAL_AGENT_LIMIT
    assert status.reason == "license_file_malformed"


# -------------------------------------------------------------- 7. export

def test_export_invalid_date_returns_400():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.export import router as export_router

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    resp = client.get("/export/json", params={"date": "garbage"})
    assert resp.status_code == 400


def test_export_format_local_converts_utc_to_local_with_offset():
    """The PDF 'Generated:' header and session start times used to print
    the raw UTC isoformat string (e.g. 2026-10-06T07:04:20.950145+00:00).
    _format_local must convert to local time and label it, for both a
    naive-UTC DB timestamp and an isoformat string with an explicit
    offset (generated_at)."""
    from api.export import _format_local

    naive_result = _format_local("2026-01-01 22:30:00")
    assert "2026" in naive_result and ":" in naive_result
    assert naive_result != "2026-01-01 22:30:00"  # actually converted, not passed through

    offset_result = _format_local("2026-01-01T22:30:00.123456+00:00")
    assert "2026" in offset_result


def test_export_pdf_header_shows_period_not_the_word_today():
    """export_pdf's header printed "Date: today" literally when called
    with no date= param, because summary['date'] is the raw query string
    ("today" by default), never resolved to an actual calendar date for
    display. The header is now a "Period: <start> to <end> <zone>" line
    built from the resolved local-day boundaries, never the literal word
    "today". The PDF's text is inside a compressed content stream, so
    this patches Canvas.drawString to capture exactly what was drawn
    instead of trying to parse the PDF bytes."""
    from datetime import datetime
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        resp = client.get("/export/pdf")
    assert resp.status_code == 200

    period_lines = [t for t in drawn if t.startswith("Period:")]
    assert len(period_lines) == 1, f"expected exactly one 'Period:' line, got {period_lines!r}"
    assert "today" not in period_lines[0], f"header still shows the literal word 'today': {period_lines[0]!r}"

    today_local = datetime.now().astimezone().date()
    assert today_local.strftime("%d %b %Y") in period_lines[0], (
        f"expected today's real local date in {period_lines[0]!r}"
    )

    assert any(t == "Vigil Audit Report" for t in drawn)


class _FixedDatetime(datetime):
    """datetime.now(tz) frozen to a fixed real moment, for deterministic
    local-day tests. Windows has no time.tzset() to actually change the
    process's effective local timezone, so export.py's _resolve_local_day/
    _local_day_bounds_utc take an explicit tz parameter instead -- this
    class only needs to fix "now" itself, not fake a system timezone."""
    _fixed = None

    @classmethod
    def now(cls, tz=None):
        if tz is not None:
            return cls._fixed.astimezone(tz)
        return cls._fixed


def test_resolve_local_day_ist_at_2am_reports_local_day_not_utc_day(monkeypatch):
    """At 02:00 IST, UTC is still the previous calendar day (IST is
    UTC+5:30, so IST midnight is 18:30 UTC the day before). "today" must
    resolve to the LOCAL day (the one a person in that timezone is
    actually living in), not whatever day it is in UTC at that instant."""
    from zoneinfo import ZoneInfo

    import api.export as export_module

    ist = ZoneInfo("Asia/Kolkata")
    fixed_now = datetime(2026, 10, 7, 2, 0, 0, tzinfo=ist)  # 2026-10-06 20:30 UTC
    assert fixed_now.astimezone(timezone.utc).date() == date(2026, 10, 6), (
        "sanity check: at this instant UTC's calendar date really is the day before IST's"
    )

    _FixedDatetime._fixed = fixed_now
    monkeypatch.setattr(export_module, "datetime", _FixedDatetime)

    day = export_module._resolve_local_day("today", tz=ist)
    assert day == date(2026, 10, 7), "the IST calendar day, not UTC's 2026-10-06"

    start_utc, end_utc = export_module._local_day_bounds_utc(day, tz=ist)
    assert start_utc == datetime(2026, 10, 6, 18, 30, tzinfo=timezone.utc)
    assert end_utc == datetime(2026, 10, 7, 18, 30, tzinfo=timezone.utc)


def test_local_day_bounds_utc_handles_us_dst_transition_day():
    """A day containing a DST transition is 23 or 25 real hours, not 24 --
    _local_day_bounds_utc must compute the end boundary from the next
    calendar DATE, not by adding a fixed 24-hour timedelta, or the period
    would be off by an hour on exactly these days. Finds a real
    transition day in America/New_York empirically (rather than hardcoding
    one) so this doesn't silently stop testing anything if the date of a
    future year's transition is ever assumed wrong."""
    from zoneinfo import ZoneInfo

    import api.export as export_module

    ny = ZoneInfo("America/New_York")

    def utc_offset_at_midnight(d):
        return datetime(d.year, d.month, d.day, tzinfo=ny).utcoffset()

    transition_day = None
    d = date(2026, 1, 1)
    for _ in range(366):
        next_d = d + timedelta(days=1)
        if utc_offset_at_midnight(d) != utc_offset_at_midnight(next_d):
            transition_day = d
            break
        d = next_d
    assert transition_day is not None, "could not find a DST transition day in 2026 for America/New_York"

    start_utc, end_utc = export_module._local_day_bounds_utc(transition_day, tz=ny)
    duration = end_utc - start_utc
    assert duration != timedelta(hours=24), (
        f"transition day {transition_day} must not be exactly 24 hours, got {duration}"
    )
    assert duration in (timedelta(hours=23), timedelta(hours=25)), (
        f"expected a 23 or 25 hour day, got {duration}"
    )


def test_resolve_local_day_with_explicit_date_ignores_tz_and_now():
    """An explicit date=YYYY-MM-DD is parsed directly regardless of
    timezone or the current moment -- only the "today" sentinel needs
    local-day resolution at all."""
    from zoneinfo import ZoneInfo

    import api.export as export_module

    day = export_module._resolve_local_day("2026-03-15", tz=ZoneInfo("America/New_York"))
    assert day == date(2026, 3, 15)


def test_resolve_local_day_utc_unchanged(monkeypatch):
    """A UTC-based machine (tz=timezone.utc, no DST ever) must behave
    exactly as the original, pre-local-day-fix code did: "today" is
    UTC's current date, and a day's bounds span exactly 24 hours."""
    import api.export as export_module

    fixed_now = datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
    _FixedDatetime._fixed = fixed_now
    monkeypatch.setattr(export_module, "datetime", _FixedDatetime)

    day = export_module._resolve_local_day("today", tz=timezone.utc)
    assert day == date(2026, 6, 15)

    start_utc, end_utc = export_module._local_day_bounds_utc(day, tz=timezone.utc)
    assert start_utc == datetime(2026, 6, 15, 0, 0, tzinfo=timezone.utc)
    assert end_utc == datetime(2026, 6, 16, 0, 0, tzinfo=timezone.utc)
    assert end_utc - start_utc == timedelta(hours=24)


# ------------------------------------------ 8. writer wedge-replace failure
#
# Covers the gap found during the 2026-09-30 soak test: _replace_wedged_
# connection's call to replace_db() was unguarded, and start_writer()'s loop
# had no except clause at all -- so a failure while replacing an already-
# wedged connection (confirmed live: replace_db() -> init_db() raising
# "database is locked" because the abandoned connection's thread was still
# holding the WAL lock) killed the entire writer task silently. Every future
# enqueue() call then hung forever while /health kept responding, which is
# worse than a clean crash since nothing external could tell the backend was
# broken. These tests exercise the real retry/escalation code paths directly
# with a synthetic replace_db() failure, since a genuine wedge is inherently
# non-deterministic (it only ever showed up twice, ~45 minutes apart, under
# sustained real load).

class _DeliberateExit(Exception):
    """Stands in for the real os._exit(1) during tests, so the escalation
    path can be asserted without actually killing the test process."""


@pytest.mark.asyncio
async def test_replace_wedged_connection_retries_transient_replace_db_failure(test_db, monkeypatch):
    agg = Aggregator()
    calls = {"n": 0}

    async def _flaky_replace_db():
        calls["n"] += 1
        if calls["n"] < 2:
            raise Exception("database is locked")
        return await database.get_db()

    monkeypatch.setattr(aggregator_module, "replace_db", _flaky_replace_db)

    await agg._replace_wedged_connection()  # must not raise

    assert calls["n"] == 2
    assert agg._connection_replace_count == 2


@pytest.mark.asyncio
async def test_replace_wedged_connection_escalates_to_exit_when_budget_exhausted(test_db, monkeypatch):
    agg = Aggregator()

    async def _always_fails():
        raise Exception("database is locked")

    def _fake_exit(code):
        raise _DeliberateExit(code)

    monkeypatch.setattr(aggregator_module, "replace_db", _always_fails)
    monkeypatch.setattr(aggregator_module.os, "_exit", _fake_exit)

    with pytest.raises(_DeliberateExit):
        await agg._replace_wedged_connection()

    # Never fell through to a bare `raise` back to the caller -- the only
    # way out of repeated replace_db() failure is the deliberate-exit path.
    assert agg._connection_replace_count == aggregator_module.MAX_CONNECTION_REPLACEMENTS + 1


@pytest.mark.asyncio
async def test_start_writer_backstop_exits_instead_of_dying_silently(test_db, monkeypatch):
    agg = Aggregator()

    async def _boom(coro_factory, future):
        raise RuntimeError("simulated unforeseen failure escaping the watchdog")

    def _fake_exit(code):
        raise _DeliberateExit(code)

    monkeypatch.setattr(agg, "_run_write_with_watchdog", _boom)
    monkeypatch.setattr(aggregator_module.os, "_exit", _fake_exit)

    future = asyncio.get_running_loop().create_future()
    await agg._write_queue.put((lambda: None, future))

    with pytest.raises(_DeliberateExit):
        await agg.start_writer()

    # The in-flight write's caller must not be left hanging forever either.
    assert future.done()
    assert isinstance(future.exception(), ConnectionWedgedError)


# ---------------------------------------- 9. unprefixed route / SPA shadowing

def test_unprefixed_routers_gated_by_frozen_flag(monkeypatch, tmp_path):
    """events/agents/alerts/.../evidence are registered twice in main.py:
    once unprefixed (dev-only -- Vite's dev server proxies /api/* to this
    backend and strips the prefix before forwarding, so the backend must
    answer the unprefixed path in that one workflow) and once under /api
    (always, since the built frontend itself always calls /api/*). Several
    of these routers' own bare paths -- /alerts, /agents, /incidents --
    also happen to be frontend screen names. Left registered unprefixed in
    a frozen build (no Vite involved there at all), they silently shadowed
    the SPA catch-all: a plain GET to /alerts returned real API JSON
    instead of falling through to spa_fallback's index.html.

    main.py's app object and its conditional include_router(...) calls run
    once, at module import time, so the only way to exercise both states is
    reloading the module with sys.frozen toggled -- nothing else in this
    suite imports main's actual `app`, per the investigation that preceded
    this fix, hence the reload/TestClient machinery below rather than a
    simpler fixture.

    A scratch {tmp_path}/frontend/index.html stands in for the real built
    frontend, purely so the SPA fallback route itself registers (it only
    does if FRONTEND_DIR exists on disk -- see main.py) and the frozen-case
    assertion below can tell "fell through to the SPA shell" apart from
    "no route matched at all". LOCALAPPDATA is also redirected to tmp_path
    for the frozen reload so get_base_path() doesn't touch the real
    %LOCALAPPDATA%\\V-LAW this machine actually uses."""
    import importlib

    from fastapi.testclient import TestClient

    import main as main_module

    frontend_dir = tmp_path / "frontend"
    frontend_dir.mkdir()
    (frontend_dir / "assets").mkdir()
    (frontend_dir / "index.html").write_text("<html>spa shell</html>")
    fake_exe = tmp_path / "backend" / "vlaw-backend.exe"
    fake_exe.parent.mkdir()

    def reload_as(frozen: bool):
        if frozen:
            monkeypatch.setattr(sys, "frozen", True, raising=False)
            monkeypatch.setattr(sys, "executable", str(fake_exe))
            monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        else:
            monkeypatch.delattr(sys, "frozen", raising=False)
        return importlib.reload(main_module)

    try:
        not_frozen = reload_as(frozen=False)
        # base_url="http://localhost" (not TestClient's "http://testserver"
        # default) so the Host header this client sends passes main.py's
        # localhost/origin guard middleware, same as any real request would.
        client = TestClient(not_frozen.app, base_url="http://localhost")
        for path in ("/alerts", "/agents", "/incidents"):
            resp = client.get(path)
            assert resp.headers["content-type"].startswith("application/json"), (
                f"dev mode (not frozen): {path} should hit the real unprefixed "
                f"router (Vite's proxy needs it), got {resp.headers['content-type']}"
            )

        frozen = reload_as(frozen=True)
        client = TestClient(frozen.app, base_url="http://localhost")
        for path in ("/alerts", "/agents", "/incidents"):
            resp = client.get(path)
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/html"), (
                f"frozen build: {path} should fall through to the SPA shell "
                f"(no router should match it unprefixed), got {resp.headers['content-type']}"
            )
        for path in ("/api/alerts", "/api/agents", "/api/incidents"):
            resp = client.get(path)
            assert resp.headers["content-type"].startswith("application/json"), (
                f"frozen build: {path} should still hit the real API route"
            )
    finally:
        # main's app object is shared module state (sys.modules["main"]) --
        # leave it reloaded back to the normal, non-frozen state regardless
        # of the above, so no later test importing from main inherits the
        # frozen reload's app/FRONTEND_DIR.
        reload_as(frozen=False)
