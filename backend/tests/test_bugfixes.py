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
from core.layer2a import check_network_destinations, check_ratio_anomaly, check_time_anomaly
import core.layer2a as layer2a
from core.layer2b import score_session_2b
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


@pytest.mark.asyncio
async def test_ratio_anomaly_write_heavy_branch_gated_off_reads_not_observable(test_db, monkeypatch):
    """FILE_READS_OBSERVABLE = False: the write-heavy ("wrote N but read
    only 0") branch must never fire, since reads are never observable on
    Windows and the check would otherwise fire on every qualifying
    session. The read-heavy branch is untouched and must still fire."""
    layer2a._alerter._last_fired.clear()

    agent_name = _uniq("claude_code_ratiotest")
    agent_id = await _make_agent(test_db, agent_name)
    prior = get_prior(agent_name)
    assert prior["read_write_ratio"]["critical"] == 25.0

    write_heavy_session = _uniq("sess")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count) VALUES (?, ?, 'file_write', '/x', 30)",
        (agent_id, write_heavy_session),
    )
    await test_db.commit()
    fired = await check_ratio_anomaly(write_heavy_session, agent_id, agent_name, prior, test_db)
    assert fired == [], "write-heavy branch must stay gated off while FILE_READS_OBSERVABLE is False"

    monkeypatch.setattr(layer2a, "FILE_READS_OBSERVABLE", True)
    fired_if_enabled = await check_ratio_anomaly(write_heavy_session, agent_id, agent_name, prior, test_db)
    assert len(fired_if_enabled) == 1, "flipping the constant back on must restore the old behavior"
    monkeypatch.undo()

    read_heavy_session = _uniq("sess")
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count) VALUES (?, ?, 'file_read', '/x', 30)",
        (agent_id, read_heavy_session),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, file_count) VALUES (?, ?, 'file_write', '/x', 1)",
        (agent_id, read_heavy_session),
    )
    await test_db.commit()
    fired = await check_ratio_anomaly(read_heavy_session, agent_id, agent_name, prior, test_db)
    assert len(fired) == 1, "the read-heavy branch is untouched by this gate and must still fire"


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


def test_wrap_line_handles_very_long_zone_name():
    """_wrap_line must split a line that is too wide for the printable
    page width into multiple lines, each one individually measuring
    within that width -- using reportlab's own stringWidth, not a
    guessed character count, since different fonts/sizes render the
    same text at different widths. Uses a deliberately long fake zone
    name (longer than any real one) rather than this machine's actual
    timezone, which varies by machine and isn't reliably long enough to
    exercise wrapping on its own."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfbase.pdfmetrics import stringWidth

    import api.export as export_module

    max_width = letter[0] - 2 * inch
    long_zone_name = "Pacific Extremely Long Fictional Standard Time For Wrap Testing Purposes Only"
    text = f"Period: 07 Oct 2026 00:00 to 08 Oct 2026 00:00 {long_zone_name}"

    lines = export_module._wrap_line(text, "Helvetica", 10, max_width)

    assert len(lines) > 1, "expected this deliberately long line to actually wrap"
    for line in lines:
        assert stringWidth(line, "Helvetica", 10) <= max_width, (
            f"wrapped line exceeds printable width: {line!r}"
        )
    # no words lost or reordered by wrapping
    assert " ".join(lines) == text


@pytest.mark.asyncio
async def test_export_pdf_no_drawn_line_exceeds_printable_width(test_db):
    """End-to-end: seeds a session with a long operator/hostname and an
    alert with a very long title, then renders the real PDF and checks
    every single drawString call reportlab actually made -- header,
    sessions, and alerts alike -- against the same max_width the PDF
    itself is laid out with. Captures the real font/size active on the
    canvas at each draw call (Canvas._fontname/_fontsize) since width
    depends on both, not just the text."""
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_pdfwraptest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")
    long_hostname = "a-very-long-workstation-hostname-" + "x" * 80
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, operator_username, operator_hostname) "
        "VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)",
        (session_id, agent_id, "a_very_long_operator_username_" + "y" * 80, long_hostname),
    )
    long_title = "Critical alert: " + "suspicious activity detected in a path " * 15
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type) "
        "VALUES (?, 'critical', ?, 'd', 'open', 'policy')",
        (agent_id, long_title),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    max_width = letter[0] - 2 * inch
    captured = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        captured.append((text, self._fontname, self._fontsize))
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        resp = client.get("/export/pdf")
    assert resp.status_code == 200
    assert len(captured) > 0

    overflowing = [
        (text, font, size, stringWidth(text, font, size))
        for text, font, size in captured
        if stringWidth(text, font, size) > max_width
    ]
    assert overflowing == [], f"drawn line(s) exceed printable width {max_width}: {overflowing}"

    # the long alert title must still appear in full somewhere across the
    # wrapped lines, not silently truncated the way line[:110] used to.
    joined = " ".join(text for text, _, _ in captured)
    assert "suspicious activity detected in a path" in joined


def test_format_duration_under_and_over_an_hour():
    from api.export import _format_duration

    assert _format_duration(45) == "0m 45s"
    assert _format_duration(125) == "2m 5s"
    assert _format_duration(3599) == "59m 59s"
    assert _format_duration(3600) == "1h 0m"
    assert _format_duration(80164) == "22h 16m"


def test_utc_offset_label_formats_positive_and_negative():
    from api.export import _utc_offset_label

    ist = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert _utc_offset_label(ist) == "UTC+05:30"

    behind = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=-4)))
    assert _utc_offset_label(behind) == "UTC-04:00"

    utc = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert _utc_offset_label(utc) == "UTC+00:00"


@pytest.mark.asyncio
async def test_export_folds_no_activity_sessions_pdf_and_json(test_db):
    """A session with started_at == ended_at and zero events this period
    is folded into one count line in the PDF and the summary line, but
    the JSON keeps every session with a no_activity flag on it. A normal
    session with real activity is listed individually with its agent
    name and period event count."""
    import re
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_noactivitytest")
    agent_id = await _make_agent(test_db, agent_name)

    real_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (real_session_id, agent_id),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'file_write', '/tmp/x.py')",
        (agent_id, real_session_id),
    )

    empty_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (empty_session_id, agent_id),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    json_resp = client.get("/export/json")
    assert json_resp.status_code == 200
    by_id = {s["id"]: s for s in json_resp.json()["sessions"]}
    assert by_id[real_session_id]["no_activity"] is False
    assert by_id[real_session_id]["event_count_in_period"] == 1
    assert by_id[real_session_id]["agent_name"] == agent_name
    assert by_id[empty_session_id]["no_activity"] is True
    assert by_id[empty_session_id]["event_count_in_period"] == 0

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        pdf_resp = client.get("/export/pdf")
    assert pdf_resp.status_code == 200

    joined = " ".join(drawn)
    # Counts are checked as "at least this test's own contribution", not
    # an exact match -- another test earlier in the same shared DB can
    # leave its own no-activity session behind (started_at == ended_at,
    # no events), which would otherwise make an exact count fragile to
    # execution order.
    fold_match = re.search(r"(\d+) sessions? with no recorded activity", joined)
    assert fold_match is not None and int(fold_match.group(1)) >= 1
    summary_match = re.search(r"\(\+(\d+) with no recorded activity\)", joined)
    assert summary_match is not None and int(summary_match.group(1)) >= 1
    assert f"agent={agent_name}" in joined
    assert "events=1" in joined
    # the empty session's own id must never appear as an individually
    # listed line
    assert empty_session_id[:8] not in joined


@pytest.mark.asyncio
async def test_export_pdf_alert_line_prefixed_with_time_and_session(test_db):
    """Superseded by grouping (see test_export_pdf_groups_alerts_by_session):
    an alert with a session_id no longer carries its own time/session
    prefix -- that moved to the group's header line, shared by every
    alert in the group. This test now checks the header carries the
    session id and a local time, and the alert's own line still carries
    its severity and title."""
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_alertprefixtest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, session_id) "
        "VALUES (?, 'critical', 'prefix test alert', 'd', 'open', 'policy', ?)",
        (agent_id, session_id),
    )
    await test_db.commit()

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

    header_idx = next(i for i, t in enumerate(drawn) if t.startswith(f"Session {session_id[:8]}"))
    header_window = " ".join(drawn[header_idx:header_idx + 6])
    assert "detected" in header_window

    alert_lines = [t for t in drawn if "prefix test alert" in t]
    assert len(alert_lines) == 1
    assert alert_lines[0] == "[CRITICAL] prefix test alert (status=open)"


@pytest.mark.asyncio
async def test_export_sessions_overlap_period_not_just_start_inside_it(test_db):
    """A session that started before today and is still running (or only
    just ended) this morning has real events inside today's report -- it
    must be listed even though its own started_at isn't inside today's
    window. A session that's fully before or fully after the period must
    not appear. Uses tz=timezone.utc so "today" is deterministic
    regardless of this machine's real timezone."""
    import api.export as export_module

    agent_name = _uniq("claude_code_overlaptest")
    agent_id = await _make_agent(test_db, agent_name)

    # Spans midnight: started well before today, still open.
    spanning_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, NULL)",
        (spanning_id, agent_id, "2026-03-14 20:00:00"),
    )
    # Fully before the period: ended before today started.
    before_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, ?)",
        (before_id, agent_id, "2026-03-13 10:00:00", "2026-03-13 11:00:00"),
    )
    # Fully after the period: starts tomorrow.
    after_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, ?)",
        (after_id, agent_id, "2026-03-16 01:00:00", "2026-03-16 02:00:00"),
    )
    # Started inside the period (the ordinary case, must still work).
    inside_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, ?, ?)",
        (inside_id, agent_id, "2026-03-15 08:00:00", "2026-03-15 09:00:00"),
    )
    await test_db.commit()

    summary = await export_module._build_summary("2026-03-15", tz=timezone.utc)
    # Scoped to this test's own agent_id -- the shared test DB can carry
    # sessions from other tests/runs, so asserting on the full returned
    # list's size would be fragile to data this test never created.
    my_sessions = [s for s in summary["sessions"] if s["agent_id"] == agent_id]
    my_session_ids = {s["id"] for s in my_sessions}

    assert spanning_id in my_session_ids, "a session spanning midnight into this period must be listed"
    assert inside_id in my_session_ids, "a session that started inside the period must still be listed"
    assert before_id not in my_session_ids, "a session fully before the period must not be listed"
    assert after_id not in my_session_ids, "a session fully after the period must not be listed"

    # the summary counts must match what's actually in the list, for this
    # test's own agent: exactly the spanning and inside sessions.
    assert my_session_ids == {spanning_id, inside_id}


@pytest.mark.asyncio
async def test_export_pdf_marks_sessions_that_began_before_the_period(test_db):
    """The spanning-midnight session's PDF line must show both started
    and ended in local time and the "(began before this period)" marker;
    a session that started inside the period must not get that marker."""
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    import api.export as export_module
    from api.export import router as export_router

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15",
            "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00",
            "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC",
            "event_count": 0,
            "sessions": [
                {
                    "id": "spanning-session-id",
                    "started_at": "2026-03-14 20:00:00",
                    "ended_at": None,
                    "operator_username": "alice",
                    "operator_hostname": "alice-pc",
                    "agent_name": "claude_code",
                    "event_count_in_period": 3,
                    "no_activity": False,
                    "resumed": False,
                },
                {
                    "id": "inside-session-id",
                    "started_at": "2026-03-15 08:00:00",
                    "ended_at": "2026-03-15 09:00:00",
                    "operator_username": "bob",
                    "operator_hostname": "bob-pc",
                    "agent_name": "codex",
                    "event_count_in_period": 1,
                    "no_activity": False,
                    "resumed": False,
                },
            ],
            "alerts": [],
            "report_notes": export_module.REPORT_NOTES,
            "coverage_available": False,
            "tracking_started_at": None,
            "active_seconds": 0,
            "period_seconds_measured": 0,
            "gaps": [],
            "short_gap_count": 0,
            "short_gap_seconds": 0,
        }

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(export_module, "_build_summary", fake_build_summary), \
         patch.object(canvas.Canvas, "drawString", capture):
        resp = client.get("/export/pdf")
    assert resp.status_code == 200

    # The marker phrase itself can be split across two wrapped sub-lines
    # (confirmed: on this machine the long local zone name pushes
    # "(began before" onto one line and "this period)" onto the next),
    # so join everything drawn before checking for it as a phrase.
    joined = " ".join(drawn)
    assert joined.count("(began before this period)") == 1, (
        "exactly the spanning session should get the marker, not the one that started inside"
    )
    assert "ended=ongoing" in joined


@pytest.mark.asyncio
async def test_export_json_includes_report_notes():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.export as export_module
    from api.export import router as export_router

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    resp = client.get("/export/json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["report_notes"] == export_module.REPORT_NOTES
    assert len(data["report_notes"]) == 8


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


# ---------------------------------------- 10. resumed (rediscovered) sessions

@pytest.mark.asyncio
async def test_touch_marks_resumed_sessions_and_reuses_them(test_db):
    """resumed=True on touch() is persisted on the new row. A later touch
    for the same agent while its session is still active reuses that same
    session_id -- a rediscovered agent that goes on to spawn something real
    doesn't get a second session, the original resumed=1 row absorbs it."""
    agent_id = await _make_agent(test_db, _uniq("resumed_touch_agent"))
    sm = SessionManager()

    resumed_session_id = await sm.touch(agent_id, resumed=True)
    cur = await test_db.execute("SELECT resumed FROM sessions WHERE id = ?", (resumed_session_id,))
    row = await cur.fetchone()
    assert row["resumed"] == 1

    same_session_id = await sm.touch(agent_id, resumed=False)
    assert same_session_id == resumed_session_id
    cur = await test_db.execute("SELECT resumed FROM sessions WHERE id = ?", (resumed_session_id,))
    row = await cur.fetchone()
    assert row["resumed"] == 1, "the existing session's resumed flag must not be overwritten by a later touch"


@pytest.mark.asyncio
async def test_touch_default_is_not_resumed(test_db):
    agent_id = await _make_agent(test_db, _uniq("fresh_touch_agent"))
    sm = SessionManager()
    session_id = await sm.touch(agent_id)
    cur = await test_db.execute("SELECT resumed FROM sessions WHERE id = ?", (session_id,))
    row = await cur.fetchone()
    assert row["resumed"] == 0


@pytest.mark.asyncio
async def test_touch_splits_session_on_long_gap(test_db, monkeypatch):
    """A gap since last_activity past SESSION_IDLE_TIMEOUT_SECONDS closes
    the stale session (backdated to that last_activity, not now) through
    the real scoring pipeline exactly once, then opens a genuinely new,
    non-resumed session -- simulating the sleep-spanning-session bug
    from the resumed-session investigation."""
    from core.baseline import Baseline

    agent_id = await _make_agent(test_db, _uniq("gapsplit_agent"))
    sm = SessionManager()

    call_count = {"n": 0}
    original_update = Baseline.update_from_session

    async def counting_update(self, session_id):
        call_count["n"] += 1
        return await original_update(self, session_id)

    monkeypatch.setattr(Baseline, "update_from_session", counting_update)

    old_session_id = await sm.touch(agent_id)
    stale_time = datetime.now(timezone.utc) - timedelta(hours=10)
    sm._active[agent_id]["last_activity"] = stale_time

    cur = await test_db.execute("SELECT session_count FROM agents WHERE id = ?", (agent_id,))
    count_before = (await cur.fetchone())["session_count"]

    new_session_id = await sm.touch(agent_id)
    assert new_session_id != old_session_id

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (old_session_id,))
    row = await cur.fetchone()
    assert row["ended_at"] == stale_time.strftime("%Y-%m-%d %H:%M:%S"), "ended_at must be backdated, not CURRENT_TIMESTAMP"

    cur = await test_db.execute("SELECT resumed FROM sessions WHERE id = ?", (new_session_id,))
    assert (await cur.fetchone())["resumed"] == 0, "a gap split must never mark the new session resumed"

    cur = await test_db.execute("SELECT session_count FROM agents WHERE id = ?", (agent_id,))
    count_after = (await cur.fetchone())["session_count"]
    assert count_after == count_before + 1

    assert call_count["n"] == 1, "baseline scoring must run exactly once for the stale session"


@pytest.mark.asyncio
async def test_touch_split_scoring_failure_does_not_block_new_session(test_db, monkeypatch, caplog):
    """If closing the stale session raises, the failure is logged but a
    new session must still be opened -- a scoring failure must never
    block new-session creation."""
    agent_id = await _make_agent(test_db, _uniq("gapsplit_fail_agent"))
    sm = SessionManager()

    old_session_id = await sm.touch(agent_id)
    sm._active[agent_id]["last_activity"] = datetime.now(timezone.utc) - timedelta(hours=10)

    async def boom(self, db, session_id, agent_id):
        raise RuntimeError("roll-up exploded")

    monkeypatch.setattr(SessionManager, "_roll_up_session_stats", boom)

    new_session_id = await sm.touch(agent_id)
    assert new_session_id != old_session_id

    cur = await test_db.execute("SELECT id FROM sessions WHERE id = ?", (new_session_id,))
    assert await cur.fetchone() is not None, "the new session must exist even though closing the old one failed"
    assert "closing stale session" in caplog.text


@pytest.mark.asyncio
async def test_touch_within_timeout_does_not_split(test_db):
    agent_id = await _make_agent(test_db, _uniq("nosplit_agent"))
    sm = SessionManager()
    session_id = await sm.touch(agent_id)
    sm._active[agent_id]["last_activity"] = datetime.now(timezone.utc) - timedelta(seconds=100)

    same_session_id = await sm.touch(agent_id)
    assert same_session_id == session_id

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (session_id,))
    assert (await cur.fetchone())["ended_at"] is None, "a normal touch within the timeout must not close the session"


@pytest.mark.asyncio
async def test_touch_concurrent_gap_split_creates_exactly_one_new_session(test_db, monkeypatch):
    """8 concurrent touch() calls on the same stale agent must not race
    into 8 duplicate replacement sessions: whichever call acquires the
    per-agent lock first does the pop-and-create, every other call finds
    that new session already registered and just returns it."""
    from core.baseline import Baseline

    agent_id = await _make_agent(test_db, _uniq("concurrent_gapsplit_agent"))
    sm = SessionManager()

    call_count = {"n": 0}
    original_update = Baseline.update_from_session

    async def counting_update(self, session_id):
        call_count["n"] += 1
        return await original_update(self, session_id)

    monkeypatch.setattr(Baseline, "update_from_session", counting_update)

    old_session_id = await sm.touch(agent_id)
    stale_time = datetime.now(timezone.utc) - timedelta(hours=10)
    sm._active[agent_id]["last_activity"] = stale_time

    cur = await test_db.execute("SELECT session_count FROM agents WHERE id = ?", (agent_id,))
    count_before = (await cur.fetchone())["session_count"]

    results = await asyncio.gather(*[sm.touch(agent_id) for _ in range(8)])

    assert len(set(results)) == 1, "all 8 concurrent calls must return the same new session id"
    new_session_id = results[0]
    assert new_session_id != old_session_id

    cur = await test_db.execute(
        "SELECT COUNT(*) c FROM sessions WHERE agent_id = ? AND id != ?", (agent_id, old_session_id),
    )
    assert (await cur.fetchone())["c"] == 1, "exactly one new session row, not 8"

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (old_session_id,))
    row = await cur.fetchone()
    assert row["ended_at"] == stale_time.strftime("%Y-%m-%d %H:%M:%S")

    cur = await test_db.execute("SELECT session_count FROM agents WHERE id = ?", (agent_id,))
    count_after = (await cur.fetchone())["session_count"]
    assert count_after == count_before + 1, "session_count must increment exactly once, not 8 times"

    assert set(sm._active.keys()) == {agent_id}
    assert sm._active[agent_id]["session_id"] == new_session_id
    assert call_count["n"] == 1, "the stale session must be scored exactly once"


@pytest.mark.asyncio
async def test_close_idle_sessions_concurrent_with_touch_gap_split(test_db, monkeypatch):
    """close_idle_sessions racing against touch()'s own gap-split for the
    same stale agent must not raise, must not close the live new
    session, and must close the stale one exactly once regardless of
    which path actually wins the race."""
    from core.baseline import Baseline

    agent_id = await _make_agent(test_db, _uniq("race_closeidle_agent"))
    sm = SessionManager()

    call_count = {"n": 0}
    original_update = Baseline.update_from_session

    async def counting_update(self, session_id):
        call_count["n"] += 1
        return await original_update(self, session_id)

    monkeypatch.setattr(Baseline, "update_from_session", counting_update)

    old_session_id = await sm.touch(agent_id)
    sm._active[agent_id]["last_activity"] = datetime.now(timezone.utc) - timedelta(hours=10)

    baseline = Baseline()
    new_session_id, _closed = await asyncio.gather(
        sm.touch(agent_id),
        sm.close_idle_sessions(baseline),
    )

    assert new_session_id != old_session_id

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (old_session_id,))
    assert (await cur.fetchone())["ended_at"] is not None, "the stale session must be closed by one path or the other"

    cur = await test_db.execute("SELECT ended_at FROM sessions WHERE id = ?", (new_session_id,))
    assert (await cur.fetchone())["ended_at"] is None, "the live new session must never be closed"

    assert sm._active[agent_id]["session_id"] == new_session_id
    assert call_count["n"] == 1, "the stale session must be scored exactly once, not by both paths"


@pytest.mark.asyncio
async def test_touch_gap_split_close_failure_still_registers_new_session(test_db, monkeypatch):
    agent_id = await _make_agent(test_db, _uniq("gapsplit_raise_agent"))
    sm = SessionManager()

    old_session_id = await sm.touch(agent_id)
    sm._active[agent_id]["last_activity"] = datetime.now(timezone.utc) - timedelta(hours=10)

    async def boom(self, db, baseline, session_id, agent_id, ended_at=None):
        raise RuntimeError("close exploded")

    monkeypatch.setattr(SessionManager, "_close_session", boom)

    new_session_id = await sm.touch(agent_id)
    assert new_session_id != old_session_id
    assert sm._active[agent_id]["session_id"] == new_session_id

    cur = await test_db.execute("SELECT id FROM sessions WHERE id = ?", (new_session_id,))
    assert await cur.fetchone() is not None


@pytest.mark.asyncio
async def test_touch_gap_split_close_does_not_swallow_cancelled_error(test_db, monkeypatch):
    agent_id = await _make_agent(test_db, _uniq("gapsplit_cancel_agent"))
    sm = SessionManager()

    await sm.touch(agent_id)
    sm._active[agent_id]["last_activity"] = datetime.now(timezone.utc) - timedelta(hours=10)

    async def cancel_boom(self, db, baseline, session_id, agent_id, ended_at=None):
        raise asyncio.CancelledError()

    monkeypatch.setattr(SessionManager, "_close_session", cancel_boom)

    with pytest.raises(asyncio.CancelledError):
        await sm.touch(agent_id)


@pytest.mark.asyncio
async def test_process_watcher_marks_first_poll_sessions_resumed(test_db):
    """ProcessWatcher's very first poll after construction (a restart)
    treats every already-running agent-matching PID as "new" since
    self._known_pids starts empty -- those sessions are opened with
    resumed=True. A PID that genuinely spawns later, after the first real
    snapshot is in hand, is not."""
    from watchers.process_watcher import ProcessWatcher

    class _FakeSessions:
        def __init__(self):
            self.calls: list[tuple[int, bool]] = []

        async def touch(self, agent_id, resumed=False):
            self.calls.append((agent_id, resumed))
            return _uniq("fake-session")

    class _FakeAttributor:
        def __init__(self, db):
            self._db = db
            self.sessions = _FakeSessions()
            self._name_by_pid: dict[int, str] = {}
            self._agent_ids: dict[str, int] = {}

        def get_named_agent_for_pid(self, pid, pid_snapshot=None):
            return self._name_by_pid.get(pid)

        def get_behaviour_score_for_pid(self, pid):
            return None

        async def get_or_create_agent(self, name, pid=None, confidence=None):
            if name not in self._agent_ids:
                self._agent_ids[name] = await _make_agent(self._db, _uniq(name))
            return self._agent_ids[name]

    attributor = _FakeAttributor(test_db)
    attributor._name_by_pid[111] = "claude_code"
    watcher = ProcessWatcher(attributor, aggregator=None)
    watcher._pid_snapshot = {111: {"name": "claude.exe", "ppid": 1, "status": "running"}}

    # First poll: current_pids == {111}, self._known_pids starts empty --
    # exactly the "already running when Vigil started" case.
    await watcher._poll_write_body({111})
    assert watcher._is_first_poll is False
    agent_id = attributor._agent_ids["claude_code"]
    assert attributor.sessions.calls == [(agent_id, True)]

    # A later poll: 111 is no longer new, but a genuinely new pid 222 for
    # the same agent must be resumed=False.
    attributor._name_by_pid[222] = "claude_code"
    watcher._pid_snapshot[222] = {"name": "claude.exe", "ppid": 111, "status": "running"}
    await watcher._poll_write_body({111, 222})
    assert attributor.sessions.calls[-1] == (agent_id, False)


@pytest.mark.asyncio
async def test_baseline_skips_resumed_and_zero_activity_sessions(test_db):
    """update_from_session() must not fold a resumed=1 session's stats
    (its duration/timing reflects Vigil's restart, not the agent) or a
    genuinely empty session's into the running baseline -- only a session
    with real activity and resumed=0 should move sample_count."""
    agent_id = await _make_agent(test_db, _uniq("baseline_resumed_agent"))
    baseline = Baseline()

    resumed_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, file_reads, file_writes, "
        "net_egress_bytes, proc_spawns, resumed) VALUES "
        "(?, ?, '2026-01-01 10:00:00', '2026-01-01 10:05:00', 500, 500, 0, 10, 1)",
        (resumed_session_id, agent_id),
    )
    empty_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, file_reads, file_writes, "
        "net_egress_bytes, proc_spawns, resumed) VALUES "
        "(?, ?, '2026-01-01 11:00:00', '2026-01-01 11:00:00', 0, 0, 0, 0, 0)",
        (empty_session_id, agent_id),
    )
    await test_db.commit()

    await baseline.update_from_session(resumed_session_id)
    await baseline.update_from_session(empty_session_id)

    cur = await test_db.execute(
        "SELECT sample_count FROM baseline WHERE agent_id = ? AND metric_name = 'file_read_count' AND metric_scope IS NULL",
        (agent_id,),
    )
    assert await cur.fetchone() is None, "neither the resumed nor the empty session should have been folded in"

    real_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, file_reads, file_writes, "
        "net_egress_bytes, proc_spawns, resumed) VALUES "
        "(?, ?, '2026-01-01 12:00:00', '2026-01-01 12:10:00', 5, 5, 0, 2, 0)",
        (real_session_id, agent_id),
    )
    await test_db.commit()
    await baseline.update_from_session(real_session_id)

    cur = await test_db.execute(
        "SELECT sample_count FROM baseline WHERE agent_id = ? AND metric_name = 'file_read_count' AND metric_scope IS NULL",
        (agent_id,),
    )
    row = await cur.fetchone()
    assert row is not None and row["sample_count"] == 1


@pytest.mark.asyncio
async def test_layer2b_history_skips_resumed_and_zero_activity_sessions(test_db):
    """get_session_history() must exclude resumed=1 rows and sessions with
    no file/network/duration activity at all, so the rolling-window
    median it feeds mad_score() isn't pulled toward zero/duplicate-
    restart artifacts that never reflect real agent behaviour."""
    from core.layer2b import get_session_history

    agent_id = await _make_agent(test_db, _uniq("layer2b_resumed_agent"))

    async def _insert_session(started, ended, resumed, file_events=0):
        session_id = _uniq("sess")
        await test_db.execute(
            "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, ?, ?, ?)",
            (session_id, agent_id, started, ended, 1 if resumed else 0),
        )
        for _ in range(file_events):
            await test_db.execute(
                "INSERT INTO events (agent_id, session_id, event_type, path, created_at) "
                "VALUES (?, ?, 'file_write', 'x', ?)",
                (agent_id, session_id, started),
            )
        await test_db.commit()
        return session_id

    await _insert_session("2026-01-01 09:00:00", "2026-01-01 09:00:00", resumed=True)
    await _insert_session("2026-01-01 09:05:00", "2026-01-01 09:05:00", resumed=True)
    await _insert_session("2026-01-01 09:10:00", "2026-01-01 09:10:00", resumed=False)  # empty, resumed=0
    await _insert_session("2026-01-01 10:00:00", "2026-01-01 10:10:00", resumed=False, file_events=5)
    await _insert_session("2026-01-01 11:00:00", "2026-01-01 11:10:00", resumed=False, file_events=8)
    await _insert_session("2026-01-01 12:00:00", "2026-01-01 12:10:00", resumed=False, file_events=3)

    history = await get_session_history(agent_id, _uniq("current-session"), test_db)

    assert len(history) == 3
    assert {h["file_event_count"] for h in history} == {5, 8, 3}


async def _insert_layer2b_session(db, agent_id, started, ended, file_events=0, resumed=False):
    session_id = _uniq("sess")
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) VALUES (?, ?, ?, ?, ?)",
        (session_id, agent_id, started, ended, 1 if resumed else 0),
    )
    for _ in range(file_events):
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) "
            "VALUES (?, ?, 'file_write', 'x', ?)",
            (agent_id, session_id, started),
        )
    await db.commit()
    return session_id


@pytest.mark.asyncio
async def test_layer2b_upward_only_low_value_no_alert(test_db):
    """A current value at or below the history's median must never fire
    a rolling_anomaly alert, even when it deviates from the median by
    far more than MAD_THRESHOLD -- mad_score is a two-sided magnitude,
    but this alert only ever means "more than usual"."""
    agent_id = await _make_agent(test_db, _uniq("layer2b_lowvalue_agent"))

    # Small counts, same ratios as before -- seal_new_events() has its
    # own batch cap, and this shared test DB accumulates unsealed events
    # across every test in the run, so inserting hundreds of rows here
    # starved an unrelated evidence-chain test of its expected seal count.
    for i, count in enumerate((8, 9, 10, 11, 12)):
        await _insert_layer2b_session(
            test_db, agent_id, f"2026-01-01 0{i}:00:00", f"2026-01-01 0{i}:10:00", file_events=count,
        )

    current_session_id = await _insert_layer2b_session(
        test_db, agent_id, "2026-01-01 20:00:00", "2026-01-01 20:10:00", file_events=2,
    )

    alert_ids = await score_session_2b(current_session_id, agent_id, "claude_code", test_db)
    assert alert_ids == [], "a value well below the median must not fire, however large the raw deviation"


@pytest.mark.asyncio
async def test_layer2b_skips_resumed_current_session(test_db):
    """A resumed=1 session's own metrics are partial (see
    core/sessions.py::touch), so it must never be scored against
    history by layer2b, even with real history and an extreme value --
    consistent with core/baseline.py skipping resumed sessions too."""
    agent_id = await _make_agent(test_db, _uniq("layer2b_resumed_current_agent"))

    for i, count in enumerate((8, 9, 10, 11, 12)):
        await _insert_layer2b_session(
            test_db, agent_id, f"2026-01-01 0{i}:00:00", f"2026-01-01 0{i}:10:00", file_events=count,
        )

    current_session_id = await _insert_layer2b_session(
        test_db, agent_id, "2026-01-01 20:00:00", "2026-01-01 20:10:00", file_events=50, resumed=True,
    )

    alert_ids = await score_session_2b(current_session_id, agent_id, "claude_code", test_db)
    assert alert_ids == [], "a resumed=1 current session must never be scored by layer2b"


@pytest.mark.asyncio
async def test_layer2b_normal_high_deviation_still_alerts(test_db):
    """The upward-only gate must not suppress a real, legitimate spike --
    a value well above the median, with a large enough MAD score, must
    still fire with correct 'more' wording."""
    agent_id = await _make_agent(test_db, _uniq("layer2b_highvalue_agent"))

    for i, count in enumerate((8, 9, 10, 11, 12)):
        await _insert_layer2b_session(
            test_db, agent_id, f"2026-01-01 0{i}:00:00", f"2026-01-01 0{i}:10:00", file_events=count,
        )

    current_session_id = await _insert_layer2b_session(
        test_db, agent_id, "2026-01-01 20:00:00", "2026-01-01 20:10:00", file_events=20,
    )

    alert_ids = await score_session_2b(current_session_id, agent_id, "claude_code", test_db)
    assert len(alert_ids) == 1

    cur = await test_db.execute("SELECT title FROM alerts WHERE id = ?", (alert_ids[0],))
    title = (await cur.fetchone())["title"]
    assert "2.0x more files" in title


@pytest.mark.asyncio
async def test_resumed_column_migration_is_idempotent():
    """A DB created before `resumed` existed (the exact pre-this-task
    sessions schema) gets the column added by _migrate(), and running
    _migrate() again on the same connection must not raise or duplicate
    the column -- the same idempotency every other ALTER TABLE in
    _migrate() already relies on."""
    import tempfile
    from pathlib import Path

    import aiosqlite

    tmp_dir = tempfile.mkdtemp(prefix="vlaw_migration_test_")
    db_path = Path(tmp_dir) / "legacy.db"

    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    try:
        schema_sql = database.SCHEMA_PATH.read_text()
        await conn.executescript(schema_sql)
        # Replace the (already-migrated) sessions table with the exact
        # pre-this-task column set, reproducing what a real live DB
        # looks like before this change ships.
        await conn.execute("DROP TABLE sessions")
        await conn.execute(
            """
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                agent_id INTEGER REFERENCES agents(id),
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ended_at TIMESTAMP,
                file_reads INTEGER DEFAULT 0,
                file_writes INTEGER DEFAULT 0,
                net_egress_bytes INTEGER DEFAULT 0,
                proc_spawns INTEGER DEFAULT 0,
                cred_accesses INTEGER DEFAULT 0,
                mcp_connects INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0,
                anomaly_score REAL DEFAULT 0,
                summary TEXT,
                operator_username TEXT,
                operator_hostname TEXT
            )
            """
        )
        await conn.commit()

        cur = await conn.execute("PRAGMA table_info(sessions)")
        columns_before = {row["name"] for row in await cur.fetchall()}
        assert "resumed" not in columns_before

        await database._migrate(conn)
        await database._migrate(conn)  # idempotent -- must not raise on a second run

        cur = await conn.execute("PRAGMA table_info(sessions)")
        columns_after = {row["name"] for row in await cur.fetchall()}
        assert "resumed" in columns_after

        session_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO sessions (id, agent_id, started_at) VALUES (?, NULL, CURRENT_TIMESTAMP)",
            (session_id,),
        )
        await conn.commit()
        cur = await conn.execute("SELECT resumed FROM sessions WHERE id = ?", (session_id,))
        row = await cur.fetchone()
        assert row["resumed"] == 0, "backfilled pre-existing rows default to not-resumed"
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_export_pdf_and_json_label_resumed_sessions(test_db):
    """A resumed=1 session is listed, not folded like a no-activity
    session, but carries "(already running when Vigil started)" in the
    PDF instead of its started_at being taken at face value. The JSON
    export carries the same fact as resumed: true/false."""
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_resumedtest")
    agent_id = await _make_agent(test_db, agent_name)

    resumed_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) "
        "VALUES (?, ?, CURRENT_TIMESTAMP, NULL, 1)",
        (resumed_session_id, agent_id),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'proc_spawn', 'x.exe')",
        (agent_id, resumed_session_id),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    json_resp = client.get("/export/json")
    assert json_resp.status_code == 200
    by_id = {s["id"]: s for s in json_resp.json()["sessions"]}
    assert by_id[resumed_session_id]["resumed"] is True

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        pdf_resp = client.get("/export/pdf")
    assert pdf_resp.status_code == 200

    # The full session line (id, agent, operator, started/ended, events,
    # and the resumed marker) can itself be split across several wrapped
    # drawString calls -- same reasoning as the existing "(began before
    # this period)" marker test above: join a small window of drawn
    # lines starting from the one that has this session's own id, rather
    # than assuming the marker lands in the same drawString call.
    start = next(i for i, t in enumerate(drawn) if resumed_session_id[:8] in t)
    window = " ".join(drawn[start:start + 4])
    assert "(already running when Vigil started)" in window


def _capture_drawn_lines(canvas_module):
    """Shared helper for the PDF-grouping tests below: patches
    Canvas.drawString to record every (x, text) actually drawn, returning
    the list (filled in once the caller's `with` block exits) and the
    context manager itself. x is captured (not just text) because
    indentation in export_pdf is a real x-offset, not leading spaces in
    the text -- _wrap_line's word-rejoin strips leading whitespace, so
    indentation can only be verified by comparing x positions."""
    from unittest.mock import patch

    drawn: list[tuple[float, str]] = []
    original = canvas_module.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append((x, text))
        return original(self, x, y, text)

    return drawn, patch.object(canvas_module.Canvas, "drawString", capture)


@pytest.mark.asyncio
async def test_export_pdf_groups_alerts_by_session(test_db):
    """Alerts sharing a session_id are grouped under one header line
    ("Session <id8> (<agent>): N alerts, highest <SEVERITY>, detected
    <time>") with one indented line per alert beneath it, instead of one
    flat line per alert. An alert with no session_id falls into a final
    "Other alerts" group."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_grouptest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (session_id, agent_id),
    )
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, session_id) "
        "VALUES (?, 'medium', 'grouped alert one', 'd', 'open', 'policy', ?)",
        (agent_id, session_id),
    )
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, session_id) "
        "VALUES (?, 'critical', 'grouped alert two', 'd', 'open', 'policy', ?)",
        (agent_id, session_id),
    )
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, session_id) "
        "VALUES (?, 'high', 'ungrouped alert', 'd', 'open', 'policy', NULL)",
        (agent_id,),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    drawn, patcher = _capture_drawn_lines(canvas)
    with patcher:
        resp = client.get("/export/pdf")
    assert resp.status_code == 200

    # The header itself (session id + agent name + counts + severity +
    # time) is long enough to wrap across several drawString calls, same
    # as the pre-existing began-before-period marker test -- join a
    # generous window rather than assuming it's one call.
    header_idx = next(i for i, (x, t) in enumerate(drawn) if t.startswith(f"Session {session_id[:8]}"))
    header_x = drawn[header_idx][0]
    header_window = " ".join(t for x, t in drawn[header_idx:header_idx + 6])
    assert f"({agent_name})" in header_window
    assert "2 alerts" in header_window
    assert "highest CRITICAL" in header_window, "the group header must report the highest severity in the group, not the first"

    search_window = drawn[header_idx:header_idx + 8]
    alert_one_x, _ = next((x, t) for x, t in search_window if "grouped alert one" in t)
    alert_two_x, _ = next((x, t) for x, t in search_window if "grouped alert two" in t)
    assert alert_one_x > header_x, "each alert line under a group header must be indented past it"
    assert alert_two_x > header_x

    # Other tests in the same shared DB can leave their own session-less
    # alerts behind, landing in this same "Other alerts" bucket ahead of
    # this test's own entry -- search generously rather than assuming
    # it's the very next line (same reasoning as the no-activity-session
    # fold test earlier in this file).
    other_idx = next(i for i, (x, t) in enumerate(drawn) if t == "Other alerts")
    assert any("ungrouped alert" in t for x, t in drawn[other_idx:other_idx + 50])


@pytest.mark.asyncio
async def test_export_pdf_alert_group_labels_out_of_period_session(test_db):
    """A session that ended before this report's period (so it is not
    listed in the Sessions section) but has an alert that fired today
    (see the resumed-session investigation: recovery can score a session
    long after it actually ended) gets "(session ended ..., before this
    period)" appended to its group header, using the session's real
    ended_at converted to local time."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("codex_outofperiodtest")
    agent_id = await _make_agent(test_db, agent_name)
    old_session_id = _uniq("sess")
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, '2020-01-01 10:00:00', '2020-01-01 11:00:00')",
        (old_session_id, agent_id),
    )
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, session_id) "
        "VALUES (?, 'high', 'late recovery alert', 'd', 'open', 'policy', ?)",
        (agent_id, old_session_id),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    json_resp = client.get("/export/json")
    assert old_session_id not in {s["id"] for s in json_resp.json()["sessions"]}, (
        "the session must genuinely be outside this report's period for this test to mean anything"
    )

    drawn, patcher = _capture_drawn_lines(canvas)
    with patcher:
        resp = client.get("/export/pdf")
    assert resp.status_code == 200

    # Long header, same wrapping caveat as the grouping test above --
    # join a window instead of assuming one drawString call.
    header_idx = next(i for i, (x, t) in enumerate(drawn) if t.startswith(f"Session {old_session_id[:8]}"))
    header_window = " ".join(t for x, t in drawn[header_idx:header_idx + 6])
    assert f"({agent_name})" in header_window
    # Computed the same way production code converts it (UTC -> local),
    # rather than hardcoding a specific offset -- this machine's local
    # zone shouldn't be assumed.
    expected_local = datetime(2020, 1, 1, 11, 0, 0, tzinfo=timezone.utc).astimezone().strftime("%d %b %H:%M:%S")
    assert f"(session ended {expected_local}, before this period)" in header_window


@pytest.mark.asyncio
async def test_export_pdf_session_markers_each_on_their_own_line(test_db):
    """Both the resumed marker and the began-before-period marker must
    each start their own indented drawString line, never appended to the
    (long) main session line."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    from api.export import router as export_router

    agent_name = _uniq("claude_code_markerlines")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")
    # started_at far enough in the past to guarantee it began before
    # today's period, resumed=1 so both markers apply at once.
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at, resumed) "
        "VALUES (?, ?, '2020-01-01 10:00:00', CURRENT_TIMESTAMP, 1)",
        (session_id, agent_id),
    )
    await test_db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'file_write', '/x')",
        (agent_id, session_id),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    drawn, patcher = _capture_drawn_lines(canvas)
    with patcher:
        resp = client.get("/export/pdf")
    assert resp.status_code == 200

    main_idx = next(i for i, (x, t) in enumerate(drawn) if t.startswith(session_id[:8]))
    main_x, _ = drawn[main_idx]
    began_idx = next(i for i, (x, t) in enumerate(drawn) if t == "(began before this period)")
    resumed_idx = next(i for i, (x, t) in enumerate(drawn) if t == "(already running when Vigil started)")
    # Each marker is its own exact, standalone drawString call -- not a
    # substring appended to a longer line -- drawn at a greater x than
    # the main session line (a real geometric indent, not leading
    # spaces in the text, which _wrap_line would have stripped anyway).
    assert drawn[began_idx][0] > main_x
    assert drawn[resumed_idx][0] > main_x
    assert resumed_idx in (began_idx + 1, began_idx - 1)
