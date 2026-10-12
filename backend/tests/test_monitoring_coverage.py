"""Tests for core/monitoring_coverage.py (the heartbeat/gap tracker) and
api/export.py's _compute_coverage (the export-time clipping/summary
logic built on top of it).

See tests/conftest.py for why VLAW_DATA_DIR is set there rather than
here -- this module must only ever touch that isolated temp DB, never
the real dev DB in backend/data/.

vigil_runs/monitoring_gaps are brand-new tables nothing else in the test
suite touches, but tests within *this* file still share one DB file for
the whole pytest process (same reasoning as test_perf_gate.py's
seeded_db) -- the local test_db fixture below clears both tables before
every test so _compute_coverage's MIN(started_at) and gap queries never
see a previous test's rows."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

import db.database as database

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def test_db():
    database._db = None
    db = await database.get_db()
    await db.execute("DELETE FROM monitoring_gaps")
    await db.execute("DELETE FROM vigil_runs")
    await db.commit()
    yield db
    await database.close_db()


def _uniq_run_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------- CoverageTracker


async def test_coverage_tick_detects_sleep_gap(test_db):
    """A tick arriving more than 90s after the previous one creates a
    "monitoring paused" gap and still advances last_seen_at."""
    from core.monitoring_coverage import REASON_SLEEP, CoverageTracker

    tracker = CoverageTracker()
    run_id = await tracker.start_run()
    assert run_id is not None

    tracker.last_seen_at = tracker.last_seen_at - timedelta(seconds=200)
    await tracker.record_tick()

    cur = await test_db.execute(
        "SELECT * FROM monitoring_gaps WHERE run_id = ? AND reason = ?", (run_id, REASON_SLEEP)
    )
    rows = await cur.fetchall()
    assert len(rows) == 1

    cur = await test_db.execute("SELECT last_seen_at FROM vigil_runs WHERE run_id = ?", (run_id,))
    assert (await cur.fetchone())["last_seen_at"] is not None


async def test_coverage_tick_under_threshold_creates_no_gap(test_db):
    """A slow tick under the 90s threshold is normal jitter, not a gap."""
    from core.monitoring_coverage import CoverageTracker

    tracker = CoverageTracker()
    run_id = await tracker.start_run()

    tracker.last_seen_at = tracker.last_seen_at - timedelta(seconds=45)
    await tracker.record_tick()

    cur = await test_db.execute("SELECT COUNT(*) c FROM monitoring_gaps WHERE run_id = ?", (run_id,))
    assert (await cur.fetchone())["c"] == 0


async def test_coverage_start_run_detects_restart_gap(test_db):
    """A second run's start_run() records the gap between the previous
    run's last heartbeat and this run's start as "Vigil was not
    running", with no minimum duration."""
    from core.monitoring_coverage import REASON_NOT_RUNNING, CoverageTracker

    tracker1 = CoverageTracker()
    run1_id = await tracker1.start_run()
    assert run1_id is not None

    past = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    await test_db.execute("UPDATE vigil_runs SET last_seen_at = ? WHERE run_id = ?", (past, run1_id))
    await test_db.commit()

    tracker2 = CoverageTracker()
    run2_id = await tracker2.start_run()
    assert run2_id is not None
    assert run2_id != run1_id

    cur = await test_db.execute(
        "SELECT * FROM monitoring_gaps WHERE run_id = ? AND reason = ?", (run2_id, REASON_NOT_RUNNING)
    )
    rows = await cur.fetchall()
    assert len(rows) == 1
    assert dict(rows[0])["gap_start"] == past


async def test_coverage_tick_handles_clock_backwards(test_db, caplog):
    """A tick where "now" is at or before the tracked last_seen_at must
    not create a gap and must not regress last_seen_at."""
    from core.monitoring_coverage import CoverageTracker

    tracker = CoverageTracker()
    await tracker.start_run()

    tracker.last_seen_at = tracker.last_seen_at + timedelta(hours=1)
    stashed = tracker.last_seen_at

    await tracker.record_tick()

    assert tracker.last_seen_at == stashed
    cur = await test_db.execute("SELECT COUNT(*) c FROM monitoring_gaps WHERE run_id = ?", (tracker.run_id,))
    assert (await cur.fetchone())["c"] == 0
    assert any("clock appears to have moved backwards" in r.message for r in caplog.records)


async def test_coverage_start_run_handles_clock_backwards_across_restart(test_db, caplog):
    """Same as above, but for the cross-run comparison: a new run whose
    real start time is at or before the previous run's recorded
    last_seen_at must not produce a "Vigil was not running" gap."""
    from core.monitoring_coverage import CoverageTracker

    tracker1 = CoverageTracker()
    run1_id = await tracker1.start_run()

    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    await test_db.execute("UPDATE vigil_runs SET last_seen_at = ? WHERE run_id = ?", (future, run1_id))
    await test_db.commit()

    tracker2 = CoverageTracker()
    run2_id = await tracker2.start_run()
    assert run2_id is not None

    cur = await test_db.execute("SELECT COUNT(*) c FROM monitoring_gaps WHERE run_id = ?", (run2_id,))
    assert (await cur.fetchone())["c"] == 0
    assert any("clock appears to have moved backwards" in r.message for r in caplog.records)


async def test_coverage_gap_math_ignores_clean_shutdown_flag(test_db):
    """clean_shutdown is informational only -- a restart gap is recorded
    identically whether the previous run was marked clean or not (the
    tray force-kills the backend on a normal quit, so this is 0 even for
    an entirely ordinary shutdown)."""
    from core.monitoring_coverage import REASON_NOT_RUNNING, CoverageTracker

    tracker_a = CoverageTracker()
    run_a_id = await tracker_a.start_run()
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    await test_db.execute("UPDATE vigil_runs SET last_seen_at = ? WHERE run_id = ?", (past, run_a_id))
    await test_db.commit()
    await tracker_a.mark_clean_shutdown()

    cur = await test_db.execute("SELECT clean_shutdown FROM vigil_runs WHERE run_id = ?", (run_a_id,))
    assert (await cur.fetchone())["clean_shutdown"] == 1

    tracker_b = CoverageTracker()
    run_b_id = await tracker_b.start_run()

    cur = await test_db.execute(
        "SELECT * FROM monitoring_gaps WHERE run_id = ? AND reason = ?", (run_b_id, REASON_NOT_RUNNING)
    )
    rows = await cur.fetchall()
    assert len(rows) == 1
    assert dict(rows[0])["gap_start"] == past


async def test_coverage_tick_db_write_failure_never_raises(test_db, monkeypatch):
    """A DB write failure during a tick must never raise, and the
    detected gap must be queued in memory rather than dropped."""
    from core.monitoring_coverage import CoverageTracker

    tracker = CoverageTracker()
    await tracker.start_run()

    async def failing_execute(*args, **kwargs):
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(test_db, "execute", failing_execute)

    tracker.last_seen_at = tracker.last_seen_at - timedelta(seconds=200)

    await tracker.record_tick()  # must not raise

    assert len(tracker.pending_gaps) == 1
    # in-memory tracking still advances even though the DB write failed
    assert tracker.last_seen_at is not None


async def test_coverage_pending_gap_retried_after_failed_insert(test_db, monkeypatch):
    """A gap that failed to insert is retried on a later tick and
    eventually lands in the database, with nothing lost."""
    from core.monitoring_coverage import CoverageTracker

    tracker = CoverageTracker()
    await tracker.start_run()

    original_execute = test_db.execute
    state = {"failed_once": False}

    async def flaky_execute(sql, *args, **kwargs):
        if "INSERT INTO monitoring_gaps" in sql and not state["failed_once"]:
            state["failed_once"] = True
            raise RuntimeError("simulated transient failure")
        return await original_execute(sql, *args, **kwargs)

    monkeypatch.setattr(test_db, "execute", flaky_execute)

    tracker.last_seen_at = tracker.last_seen_at - timedelta(seconds=200)
    await tracker.record_tick()
    assert len(tracker.pending_gaps) == 1

    await tracker.record_tick()
    assert len(tracker.pending_gaps) == 0

    cur = await test_db.execute("SELECT COUNT(*) c FROM monitoring_gaps WHERE run_id = ?", (tracker.run_id,))
    assert (await cur.fetchone())["c"] == 1


# --------------------------------------------------- _compute_coverage


async def test_compute_coverage_clips_gaps_to_period(test_db):
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-01 00:00:00", "2026-01-03 00:00:00"),
    )
    # Spans from before the period into it: only the 2 hours inside the
    # period (00:00-02:00) should count.
    await test_db.execute(
        "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES (?, ?, ?, ?)",
        (run_id, "2026-01-01 22:00:00", "2026-01-02 02:00:00", "monitoring paused (computer likely asleep, or Vigil was suspended)"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["coverage_available"] is True
    assert len(coverage["gaps"]) == 1
    gap = coverage["gaps"][0]
    assert gap["start"] == period_start.isoformat()
    assert gap["duration_seconds"] == 2 * 3600
    assert coverage["period_seconds_measured"] == 24 * 3600
    assert coverage["active_seconds"] == 24 * 3600 - 2 * 3600


async def test_compute_coverage_excludes_gap_fully_outside_period(test_db):
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-01 00:00:00", "2026-01-03 00:00:00"),
    )
    await test_db.execute(
        "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES (?, ?, ?, ?)",
        (run_id, "2026-01-01 05:00:00", "2026-01-01 06:00:00", "Vigil was not running"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["gaps"] == []
    assert coverage["active_seconds"] == coverage["period_seconds_measured"] == 24 * 3600


async def test_compute_coverage_folds_short_gaps(test_db):
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-01 00:00:00", "2026-01-03 00:00:00"),
    )
    await test_db.execute(
        "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES (?, ?, ?, ?)",
        (run_id, "2026-01-02 01:00:00", "2026-01-02 01:00:10", "Vigil was not running"),
    )
    await test_db.execute(
        "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES (?, ?, ?, ?)",
        (run_id, "2026-01-02 02:00:00", "2026-01-02 02:00:20", "Vigil was not running"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["gaps"] == []
    assert coverage["short_gap_count"] == 2
    assert coverage["short_gap_seconds"] == 30


async def test_compute_coverage_period_partly_before_tracking(test_db):
    """Tracking began partway through the report period -- the measured
    span (and active_seconds/period_seconds_measured) must exclude
    everything before that, not just gap time."""
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-02 12:00:00", "2026-01-03 00:00:00"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["coverage_available"] is True
    assert coverage["tracking_started_at"] == "2026-01-02T12:00:00+00:00"
    assert coverage["period_seconds_measured"] == 12 * 3600


async def test_compute_coverage_whole_period_before_tracking(test_db):
    """If coverage tracking only began after the entire report period,
    coverage_available must be False rather than showing a misleading
    0%/100% figure."""
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-05 00:00:00", "2026-01-05 01:00:00"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["coverage_available"] is False


async def test_compute_coverage_no_runs_ever_recorded(test_db):
    """No vigil_runs row at all (coverage feature just added, nothing
    recorded yet) is the same "not available" case, with no tracking
    start time to report either."""
    from api.export import _compute_coverage

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["coverage_available"] is False
    assert coverage["tracking_started_at"] is None


async def test_compute_coverage_generated_midday_uses_now_as_end(test_db):
    """A report generated mid-day measures only up to that moment, not
    the full nominal period end."""
    from api.export import _compute_coverage

    run_id = _uniq_run_id()
    await test_db.execute(
        "INSERT INTO vigil_runs (run_id, started_at, last_seen_at, clean_shutdown) VALUES (?, ?, ?, 0)",
        (run_id, "2026-01-01 00:00:00", "2026-01-02 12:00:00"),
    )
    await test_db.commit()

    period_start = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    period_end = datetime(2026, 1, 3, 0, 0, 0, tzinfo=timezone.utc)
    generated_at = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)

    coverage = await _compute_coverage(test_db, period_start, period_end, generated_at)
    assert coverage["period_seconds_measured"] == 12 * 3600


# --------------------------------------------------- end-to-end


async def test_export_endpoints_reflect_a_real_tracked_gap(test_db):
    """Full chain, no mocking: a real CoverageTracker run and tick create
    a real gap, and both /export/json and /export/pdf (through
    _build_summary) pick it up."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from core.monitoring_coverage import CoverageTracker
    from api.export import router as export_router

    tracker = CoverageTracker()
    run_id = await tracker.start_run()
    assert run_id is not None

    # Push this run's own started_at (and therefore tracking_started_at)
    # 10 minutes into the past, so a 200s-ago gap measured from the real
    # "now" at tick time is safely after started_at -- rewinding
    # last_seen_at directly from the real started_at would put the
    # simulated gap before tracking_started_at and get clipped to
    # nothing, which isn't a realistic scenario (a real gap can never
    # start before the run that detects it began).
    earlier_started_at = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    await test_db.execute("UPDATE vigil_runs SET started_at = ? WHERE run_id = ?", (earlier_started_at, run_id))
    await test_db.commit()

    tracker.last_seen_at = tracker.last_seen_at - timedelta(seconds=200)
    await tracker.record_tick()

    app = FastAPI()
    app.include_router(export_router)
    client = TestClient(app)

    resp = client.get("/export/json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["coverage_available"] is True
    assert data["period_seconds_measured"] > 0
    assert len(data["gaps"]) == 1
    assert data["gaps"][0]["reason"] == "monitoring paused (computer likely asleep, or Vigil was suspended)"
    assert (
        "Vigil records only while it is running. Periods when it was not running, "
        "for example when the computer was asleep, are listed under Monitoring coverage in this report."
    ) in data["report_notes"]

    resp_pdf = client.get("/export/pdf")
    assert resp_pdf.status_code == 200
    assert len(resp_pdf.content) > 0
