"""Regression tests for the P2a pilot-trust fixes, branch
pilot/p1-backend-safety (HEAD 2c47944):
  1. core/alerter.py   -- persisted open-duplicate guard (reason/session/target)
  4. main.py / api/alerts.py -- stats cache invalidation on resolve
  7. db/database.py    -- policy file BOM tolerance

See tests/conftest.py for why VLAW_DATA_DIR is set there rather than here --
this module (and anything it imports) must only ever touch that isolated
temp DB, never the real dev DB in backend/data/."""

import json
import uuid

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

import db.database as database
import main as main_module

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def test_db():
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


# -------------------------------------------- 1. duplicate alert guard

async def test_fire_alert_suppresses_open_duplicate_after_in_memory_reset(test_db):
    """Simulates the exact restart scenario that produced two identical
    open time_anomaly alerts: the in-memory _last_fired dict is empty (as
    it would be right after a restart), but an earlier alert for the same
    agent/reason/session/target is still open in the database. The second
    call must not create a second row."""
    from core.alerter import Alerter

    alerter = Alerter()
    agent_name = _uniq("claude_code_duptest")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")

    first_id = await alerter.fire_alert(
        agent_id, "critical",
        title="codex active at 3:30 AM with no user activity for 14 hours",
        description="first firing",
        reason="time_anomaly",
        rule_type="time_anomaly",
        target=session_id,
        session_id=session_id,
    )
    assert first_id is not None

    # A fresh Alerter() has an empty _last_fired -- this is what happens
    # across a backend restart, since that dict is in-memory only.
    second_alerter = Alerter()
    second_id = await second_alerter.fire_alert(
        agent_id, "critical",
        title="codex active at 3:30 AM with no user activity for 14 hours",
        description="second firing, same session, after a simulated restart",
        reason="time_anomaly",
        rule_type="time_anomaly",
        target=session_id,
        session_id=session_id,
    )
    assert second_id is None, "duplicate open alert for the same agent/reason/session/target must be suppressed"

    cur = await test_db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE agent_id = ? AND reason = 'time_anomaly'", (agent_id,)
    )
    assert (await cur.fetchone())["c"] == 1


async def test_fire_alert_allows_new_alert_after_first_is_resolved(test_db):
    """Once the existing open alert is resolved, the same condition firing
    again must be allowed to create a new one -- the guard is "no two
    open duplicates", not "never again"."""
    from core.alerter import Alerter

    alerter = Alerter()
    agent_name = _uniq("claude_code_duptest2")
    agent_id = await _make_agent(test_db, agent_name)
    session_id = _uniq("sess")

    first_id = await alerter.fire_alert(
        agent_id, "high", title="t1", description="d1",
        reason="ratio_anomaly", rule_type="ratio_anomaly",
        target=session_id, session_id=session_id,
    )
    assert first_id is not None

    await test_db.execute("UPDATE alerts SET status = 'dismissed' WHERE id = ?", (first_id,))
    await test_db.commit()

    # A fresh instance, same as the previous test, so the in-memory
    # window (which by design still blocks a repeat on the SAME Alerter
    # instance regardless of status) isn't what's under test here -- only
    # the persisted guard's own resolved-clears-it behavior is.
    second_alerter = Alerter()
    second_id = await second_alerter.fire_alert(
        agent_id, "high", title="t2", description="d2",
        reason="ratio_anomaly", rule_type="ratio_anomaly",
        target=session_id, session_id=session_id,
    )
    assert second_id is not None, "a new alert must be allowed once the previous one is no longer open"


async def test_fire_alert_does_not_cross_suppress_different_reasons(test_db):
    """Two different reasons for the same agent/session/target (e.g. a
    path that is both a credential path and out of scope) must not
    suppress each other just because they'd share rule_type='policy'."""
    from core.alerter import Alerter

    alerter = Alerter()
    agent_name = _uniq("claude_code_duptest3")
    agent_id = await _make_agent(test_db, agent_name)
    path = "/tmp/shared_target.env"

    cred_id = await alerter.fire_alert(
        agent_id, "high", title="Credential path accessed", description="d1",
        reason="credential_access", rule_type="policy", target=path,
    )
    scope_id = await alerter.fire_alert(
        agent_id, "medium", title="Out-of-scope directory access", description="d2",
        reason="out_of_scope_access", rule_type="policy", target=path,
    )
    assert cred_id is not None
    assert scope_id is not None
    assert cred_id != scope_id


async def test_fire_alert_never_suppresses_red_line_duplicates(test_db):
    """red_line alerts cannot be resolved from the UI (see resolve_alert's
    403), so one stays open forever. They also have no session_id, like
    every event-based alert. If the persisted guard applied here, the
    first open red_line alert for an agent/reason/target would silently
    suppress every real repeat safety violation for the rest of this
    agent's life -- exactly the evidence this system exists to keep. Both
    firings here must be recorded, same as before this guard existed."""
    from core.alerter import Alerter

    alerter = Alerter()
    agent_name = _uniq("claude_code_redlinetest")
    agent_id = await _make_agent(test_db, agent_name)
    path = "~/.ssh/id_rsa"

    first_id = await alerter.fire_alert(
        agent_id, "critical", title="Red Line: SSH key accessed", description="d1",
        reason="red_line_ssh_access", rule_type="red_line", target=path,
    )
    second_alerter = Alerter()
    second_id = await second_alerter.fire_alert(
        agent_id, "critical", title="Red Line: SSH key accessed", description="d2",
        reason="red_line_ssh_access", rule_type="red_line", target=path,
    )

    assert first_id is not None
    assert second_id is not None, "a second red_line violation must never be silently dropped"
    assert first_id != second_id

    cur = await test_db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE agent_id = ? AND reason = 'red_line_ssh_access' AND status = 'open'",
        (agent_id,),
    )
    assert (await cur.fetchone())["c"] == 2


async def test_fire_alert_never_suppresses_duplicates_with_no_session_id(test_db):
    """Same as the red_line case but for an ordinary (non-red_line) event-
    based alert with no session_id -- e.g. credential_access fired
    directly from a file-watcher event, outside any session-close
    pipeline. Behavior here must be exactly what it was before the
    persisted guard existed: both recorded, same in-memory dedup window
    as always (a fresh Alerter() per call bypasses that window, isolating
    this test to the persisted guard's own behavior)."""
    from core.alerter import Alerter

    agent_name = _uniq("claude_code_nosessiontest")
    agent_id = await _make_agent(test_db, agent_name)
    path = "/tmp/shared.env"

    first_id = await Alerter().fire_alert(
        agent_id, "high", title="Credential path accessed", description="d1",
        reason="credential_access", rule_type="policy", target=path,
    )
    second_id = await Alerter().fire_alert(
        agent_id, "high", title="Credential path accessed", description="d2",
        reason="credential_access", rule_type="policy", target=path,
    )

    assert first_id is not None
    assert second_id is not None, "event-based alerts with no session_id must not be suppressed by the persisted guard"
    assert first_id != second_id


# -------------------------------------------- 4. stats cache invalidation

async def test_resolve_alert_invalidates_stats_cache(test_db):
    """/api/stats caches for 2s so repeated polls don't repeat the query
    cost. Without invalidating that cache on resolve, needs_review would
    keep showing the pre-resolve count for up to that long -- this test
    calls /api/stats twice back to back, with no sleep, so it only passes
    if the resolve handler itself cleared the cache."""
    agent_id = await _make_agent(test_db, _uniq("claude_code_cachetest"))
    cur = await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type) "
        "VALUES (?, 'critical', 'cache invalidation test alert', 'test', 'open', 'policy')",
        (agent_id,),
    )
    await test_db.commit()
    alert_id = cur.lastrowid

    client = TestClient(main_module.app, base_url="http://localhost")

    main_module._stats_cache["data"] = None
    before = client.get("/api/stats").json()
    assert before["needs_review"] >= 1

    resp = client.post(f"/api/alerts/{alert_id}/resolve", json={"action": "dismiss"})
    assert resp.status_code == 200

    after = client.get("/api/stats").json()
    assert after["needs_review"] == before["needs_review"] - 1


async def test_bulk_dismiss_invalidates_stats_cache(test_db):
    agent_id = await _make_agent(test_db, _uniq("claude_code_cachetest2"))
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type) "
        "VALUES (?, 'high', 'bulk dismiss cache test', 'test', 'open', 'policy')",
        (agent_id,),
    )
    await test_db.commit()

    client = TestClient(main_module.app, base_url="http://localhost")

    main_module._stats_cache["data"] = None
    before = client.get("/api/stats").json()
    assert before["needs_review"] >= 1

    resp = client.post("/api/alerts/bulk-dismiss", params={"severity": "high"})
    assert resp.status_code == 200
    assert resp.json()["dismissed"] >= 1

    after = client.get("/api/stats").json()
    assert after["needs_review"] < before["needs_review"]


# -------------------------------------------------- 7. policy file BOM

async def test_seed_policy_tolerates_utf8_bom(test_db, tmp_path, monkeypatch):
    policy_file = tmp_path / "vlaw-policy.json"
    # A key not used by the real default policy file (also seeded, with
    # ON CONFLICT DO NOTHING, earlier when test_db's get_db() first ran
    # init_db()) -- a real key here would silently keep its already-
    # seeded value and this test would pass for the wrong reason.
    content = '{"test_bom_marker_key": ["C:\\\\work"]}'
    # Write the real 3-byte UTF-8 BOM followed by otherwise-valid JSON --
    # this is exactly what Windows PowerShell's `Set-Content -Encoding utf8`
    # produces, which is how this file has gotten corrupted in practice.
    policy_file.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
    monkeypatch.setattr(database, "POLICY_FILE", policy_file)

    await database._seed_policy(test_db)

    cur = await test_db.execute("SELECT policy_value FROM policy WHERE policy_key = 'test_bom_marker_key'")
    row = await cur.fetchone()
    assert row is not None
    assert json.loads(row["policy_value"]) == ["C:\\work"]


async def test_seed_policy_falls_back_on_invalid_json(test_db, tmp_path, monkeypatch, caplog):
    policy_file = tmp_path / "vlaw-policy.json"
    policy_file.write_text("not valid json{{{", encoding="utf-8")
    monkeypatch.setattr(database, "POLICY_FILE", policy_file)

    # Must not raise -- startup must not be blocked by a corrupt policy file.
    await database._seed_policy(test_db)

    assert any("policy file" in r.message and "invalid" in r.message for r in caplog.records)


async def test_seed_policy_falls_back_on_non_object_json(test_db, tmp_path, monkeypatch, caplog):
    policy_file = tmp_path / "vlaw-policy.json"
    policy_file.write_text("[1, 2, 3]", encoding="utf-8")
    monkeypatch.setattr(database, "POLICY_FILE", policy_file)

    await database._seed_policy(test_db)

    assert any("policy file" in r.message and "invalid" in r.message for r in caplog.records)


# -------------------------------------------------- 8. title encoding

async def test_alert_title_em_dash_round_trips_over_api(test_db):
    """Diagnoses the garbled-em-dash report: an alert title containing a
    real em-dash (U+2014), fetched over /api/alerts exactly as the
    frontend and any other HTTP client would, must come back byte-correct
    UTF-8 with a charset-qualified Content-Type. Isolated router (not
    main_module.app) so this doesn't boot the full app's watcher threads."""
    from fastapi import FastAPI

    from api.alerts import router as alerts_router

    agent_id = await _make_agent(test_db, _uniq("claude_code_encodingtest"))
    em_dash_title = "codex active at 3:30 AM — with no user activity for 14 hours"
    await test_db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type) "
        "VALUES (?, 'critical', ?, 'd', 'open', 'time_anomaly')",
        (agent_id, em_dash_title),
    )
    await test_db.commit()

    app = FastAPI()
    app.include_router(alerts_router, prefix="/api")
    client = TestClient(app, base_url="http://localhost")

    resp = client.get("/api/alerts", params={"status": "open"})
    assert resp.status_code == 200

    content_type = resp.headers.get("content-type", "")
    # FastAPI/Starlette's default JSONResponse sends "application/json"
    # with no charset parameter. That is spec-correct -- RFC 8259 mandates
    # JSON text be UTF-8 and explicitly says no charset parameter is
    # needed -- but record what's actually sent so this test documents
    # the real header rather than assuming it.
    assert content_type.startswith("application/json")

    raw = resp.content
    assert "—".encode("utf-8") in raw, "em-dash must be present as real UTF-8 bytes on the wire, not mangled"

    titles = [a["title"] for a in resp.json()["alerts"]]
    assert em_dash_title in titles, "em-dash must round-trip correctly through json.loads on the client side"
