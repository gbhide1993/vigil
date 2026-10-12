"""Dashboard status and alert triage: the headline status/badge only counts
alerts detected in the last 24 hours (core/alert_status.py), and old open
alerts can be resolved in bulk without deleting anything
(api/alerts.py::resolve_older_alerts). See conftest.py for why
VLAW_DATA_DIR is set there rather than here.

The test DB is shared across the run and other tests leave open alerts in
it, so each test parks every existing open alert under another status for
its duration and restores them afterwards."""

import uuid

import pytest
import pytest_asyncio

import api.alerts as alerts_module
import db.database as database
from core.alert_status import alert_status_counts, status_level

PARKED = "parked_for_triage_test"


@pytest_asyncio.fixture
async def db():
    database._db = None
    conn = await database.get_db()
    await conn.execute("UPDATE alerts SET status = ? WHERE status = 'open'", (PARKED,))
    await conn.commit()
    agent = f"claude_code_triage_{uuid.uuid4().hex[:8]}"
    cur = await conn.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (agent, agent),
    )
    await conn.commit()
    conn.test_agent_id = cur.lastrowid
    yield conn
    await conn.execute("DELETE FROM alerts WHERE agent_id = ?", (conn.test_agent_id,))
    await conn.execute("UPDATE alerts SET status = 'open' WHERE status = ?", (PARKED,))
    await conn.commit()
    try:
        import main as main_module
        main_module._stats_cache["data"] = None
    except Exception:
        pass
    await database.close_db()


async def _alert(db, severity, age, status="open", rule_type="policy", title="t"):
    """age is a SQLite modifier like '-2 hours' or '-10 days'."""
    cur = await db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, created_at) "
        "VALUES (?, ?, ?, 'd', ?, ?, datetime('now', ?))",
        (db.test_agent_id, severity, title, status, rule_type, age),
    )
    await db.commit()
    return cur.lastrowid


async def _level(db):
    return status_level(await alert_status_counts(db))


# ------------------------------------------------------------ status rules

@pytest.mark.asyncio
async def test_green_when_nothing_is_open(db):
    counts = await alert_status_counts(db)
    assert counts == {"needs_review": 0, "open_medium_24h": 0, "older_open": 0, "needs_review_total": 0}
    assert status_level(counts) == "green"


@pytest.mark.asyncio
@pytest.mark.parametrize("severity", ["high", "critical"])
async def test_red_for_open_high_or_critical_in_last_24_hours(db, severity):
    await _alert(db, severity, "-2 hours")
    counts = await alert_status_counts(db)
    assert counts["needs_review"] == 1
    assert status_level(counts) == "red"


@pytest.mark.asyncio
async def test_old_high_alert_does_not_make_status_red(db):
    await _alert(db, "high", "-30 hours")
    await _alert(db, "critical", "-20 days")
    counts = await alert_status_counts(db)
    assert counts["needs_review"] == 0
    assert counts["older_open"] == 2
    assert counts["needs_review_total"] == 2          # the all-time total is still available
    assert status_level(counts) == "green"


@pytest.mark.asyncio
async def test_amber_only_for_open_medium_in_last_24_hours(db):
    await _alert(db, "medium", "-3 hours")
    counts = await alert_status_counts(db)
    assert counts["open_medium_24h"] == 1 and counts["needs_review"] == 0
    assert status_level(counts) == "amber"


@pytest.mark.asyncio
async def test_old_medium_and_any_low_do_not_change_status(db):
    await _alert(db, "medium", "-40 hours")
    await _alert(db, "low", "-1 hours")
    await _alert(db, "low", "-5 days")
    counts = await alert_status_counts(db)
    assert counts["open_medium_24h"] == 0
    assert counts["older_open"] == 1                    # only the old medium; lows are never "older open"
    assert status_level(counts) == "green"


@pytest.mark.asyncio
async def test_red_wins_over_amber_and_closed_alerts_are_ignored(db):
    await _alert(db, "medium", "-1 hours")
    await _alert(db, "high", "-1 hours", status="dismissed")
    await _alert(db, "critical", "-1 hours", status="resolved")
    assert await _level(db) == "amber"
    await _alert(db, "high", "-1 hours")
    assert await _level(db) == "red"


@pytest.mark.asyncio
async def test_window_boundary_is_24_hours(db):
    await _alert(db, "high", "-23 hours")
    assert await _level(db) == "red"
    await db.execute("UPDATE alerts SET created_at = datetime('now', '-25 hours') WHERE agent_id = ?", (db.test_agent_id,))
    await db.commit()
    assert await _level(db) == "green"


# --------------------------------------------------------- stats / badge

@pytest.mark.asyncio
async def test_stats_badge_counts_only_recent_open_high_and_critical(db):
    import main as main_module

    await _alert(db, "high", "-1 hours")
    await _alert(db, "critical", "-5 hours")
    await _alert(db, "high", "-3 days")
    await _alert(db, "medium", "-1 hours")
    main_module._stats_cache["data"] = None

    stats = await main_module.get_stats()
    assert stats["needs_review"] == 2                  # the sidebar badge and tray tooltip
    assert stats["needs_review_total"] == 3            # all-time, still available
    assert stats["open_medium_24h"] == 1
    assert stats["older_open"] == 1
    assert stats["status_level"] == "red"


@pytest.mark.asyncio
async def test_alerts_endpoint_since_hours_filter(db):
    recent = await _alert(db, "high", "-2 hours")
    await _alert(db, "high", "-3 days")
    data = await alerts_module._get_alerts_data(
        db, "open", "high,critical", db.test_agent_id, None, 50, 0, since_hours=24,
    )
    assert [a["id"] for a in data["alerts"]] == [recent]


# ---------------------------------------------------- bulk resolve (older)

async def _table_snapshot(db):
    cur = await db.execute("SELECT * FROM alerts ORDER BY id")
    return [dict(r) for r in await cur.fetchall()]


async def _seed_old_and_new(db):
    ids = {
        "old_low": await _alert(db, "low", "-10 days"),
        "old_medium": await _alert(db, "medium", "-9 days"),
        "old_high": await _alert(db, "high", "-8 days"),
        "old_critical_policy": await _alert(db, "critical", "-8 days"),
        "old_red_high": await _alert(db, "high", "-12 days", rule_type="red_line"),
        "old_red_critical": await _alert(db, "critical", "-12 days", rule_type="red_line"),
        "new_high": await _alert(db, "high", "-2 days"),
        "old_dismissed": await _alert(db, "high", "-20 days", status="dismissed"),
    }
    return ids


@pytest.mark.asyncio
async def test_dry_run_changes_nothing_and_reports_counts(db):
    await _seed_old_and_new(db)
    before = await _table_snapshot(db)
    audit_before = (await (await db.execute("SELECT COUNT(*) c FROM audit_log")).fetchone())["c"]

    result = await alerts_module.resolve_older_alerts(days=7, dry_run=True, include_red_line=False, actor="admin")

    assert result["dry_run"] is True
    assert result["count"] == 4                       # low, medium, high, critical policy alerts
    assert result["by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert result["red_line_skipped"] == 2
    assert await _table_snapshot(db) == before
    assert (await (await db.execute("SELECT COUNT(*) c FROM audit_log")).fetchone())["c"] == audit_before


@pytest.mark.asyncio
async def test_bulk_resolve_changes_only_status_and_note_and_deletes_nothing(db):
    ids = await _seed_old_and_new(db)
    before = {r["id"]: r for r in await _table_snapshot(db)}
    total_before = len(before)
    events_before = (await (await db.execute("SELECT COUNT(*) c FROM events")).fetchone())["c"]

    result = await alerts_module.resolve_older_alerts(days=7, dry_run=False, include_red_line=False, actor="admin")
    assert result["count"] == 4

    after = {r["id"]: r for r in await _table_snapshot(db)}
    assert len(after) == total_before, "nothing may be deleted"
    assert (await (await db.execute("SELECT COUNT(*) c FROM events")).fetchone())["c"] == events_before

    resolved_ids = {ids["old_low"], ids["old_medium"], ids["old_high"], ids["old_critical_policy"]}
    changing_columns = {"status", "resolved_by", "resolved_at", "resolution_note"}
    for alert_id, old in before.items():
        new = after[alert_id]
        if alert_id in resolved_ids:
            assert new["status"] == "resolved"
            assert new["resolution_note"] == "bulk resolved (older than 7 days)"
            assert new["resolved_by"] == "admin" and new["resolved_at"] is not None
            for column in old:
                if column not in changing_columns:
                    assert new[column] == old[column], f"{column} must not change"
        else:
            assert new == old, f"alert {alert_id} must be untouched"

    cur = await db.execute(
        "SELECT COUNT(*) c FROM audit_log WHERE action = 'bulk_resolve_older' AND entity_id IN (%s)"
        % ",".join("?" * len(resolved_ids)),
        tuple(resolved_ids),
    )
    assert (await cur.fetchone())["c"] == 4


@pytest.mark.asyncio
async def test_red_line_alerts_are_skipped_unless_the_box_is_ticked(db):
    ids = await _seed_old_and_new(db)

    await alerts_module.resolve_older_alerts(days=7, dry_run=False, include_red_line=False, actor="admin")
    cur = await db.execute("SELECT status FROM alerts WHERE id IN (?, ?)", (ids["old_red_high"], ids["old_red_critical"]))
    assert [r["status"] for r in await cur.fetchall()] == ["open", "open"]

    dry = await alerts_module.resolve_older_alerts(days=7, dry_run=True, include_red_line=True, actor="admin")
    assert dry["count"] == 2 and dry["by_severity"]["high"] == 1 and dry["by_severity"]["critical"] == 1
    assert dry["red_line_skipped"] == 0

    result = await alerts_module.resolve_older_alerts(days=7, dry_run=False, include_red_line=True, actor="admin")
    assert result["count"] == 2
    cur = await db.execute("SELECT status, resolution_note FROM alerts WHERE id IN (?, ?)", (ids["old_red_high"], ids["old_red_critical"]))
    rows = [dict(r) for r in await cur.fetchall()]
    assert all(r["status"] == "resolved" and r["resolution_note"] == "bulk resolved (older than 7 days)" for r in rows)


@pytest.mark.asyncio
async def test_age_threshold_and_note_follow_the_days_argument(db):
    a_10d = await _alert(db, "medium", "-10 days")
    a_20d = await _alert(db, "medium", "-20 days")

    await alerts_module.resolve_older_alerts(days=14, dry_run=False, include_red_line=False, actor="admin")
    cur = await db.execute("SELECT id, status, resolution_note FROM alerts WHERE id IN (?, ?)", (a_10d, a_20d))
    rows = {r["id"]: dict(r) for r in await cur.fetchall()}
    assert rows[a_10d]["status"] == "open"
    assert rows[a_20d]["status"] == "resolved"
    assert rows[a_20d]["resolution_note"] == "bulk resolved (older than 14 days)"


@pytest.mark.asyncio
async def test_resolving_old_alerts_clears_the_older_open_line_and_keeps_recent_status(db):
    await _alert(db, "high", "-9 days")
    recent = await _alert(db, "high", "-1 hours")
    assert (await alert_status_counts(db))["older_open"] == 1

    await alerts_module.resolve_older_alerts(days=7, dry_run=False, include_red_line=False, actor="admin")
    counts = await alert_status_counts(db)
    assert counts["older_open"] == 0
    assert counts["needs_review"] == 1 and status_level(counts) == "red"
    cur = await db.execute("SELECT status FROM alerts WHERE id = ?", (recent,))
    assert (await cur.fetchone())["status"] == "open"


@pytest.mark.asyncio
async def test_nothing_to_resolve_is_a_clean_no_op(db):
    result = await alerts_module.resolve_older_alerts(days=7, dry_run=False, include_red_line=False, actor="admin")
    assert result["count"] == 0 and result["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_ui_wires_the_triage_features():
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "frontend" / "src"
    if not src.exists():
        pytest.skip("frontend sources not present")
    status = (src / "components" / "Status.jsx").read_text(encoding="utf-8")
    assert "No open high-severity alerts in the last 24 hours" in status
    assert "older open alert" in status
    alerts = (src / "components" / "Alerts.jsx").read_text(encoding="utf-8")
    assert "Resolve older alerts" in alerts and "Also include red-line alerts" in alerts
    assert "dryRun: true" in alerts
