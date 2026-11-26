"""The alerts list is capped by the API's default page size (api/alerts.py limit=50), not by the store. The response
carries the total and a page offset; the tray counts through the qualifying filter. See conftest.py for why
VLAW_DATA_DIR is set there."""

import uuid

import pytest
import pytest_asyncio

import api.alerts as alerts_api
import db.database as database


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    _agents.clear()
    yield conn
    for agent_id in _agents:      # the test database is shared by the whole run: leave nothing behind
        await conn.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
    await conn.commit()
    await database.close_db()


_agents: list = []


async def _agent(db):
    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"a_{uuid.uuid4().hex[:8]}",))
    await db.commit()
    _agents.append(cur.lastrowid)
    return cur.lastrowid


async def _alerts(db, agent_id, n, severity, rule_type="policy"):
    for i in range(n):
        await db.execute(
            "INSERT INTO alerts (agent_id, severity, title, description, rule_type) VALUES (?, ?, ?, 'd', ?)",
            (agent_id, severity, f"{severity} {i}", rule_type),
        )
    await db.commit()


@pytest.mark.asyncio
async def test_the_default_page_is_50_but_the_total_and_the_next_page_are_there(db):
    agent_id = await _agent(db)
    await _alerts(db, agent_id, 120, "low")
    first = await alerts_api.get_alerts(status="open", limit=50, offset=0, severity=None, agent=agent_id, session_id=None, since_hours=None, qualifying=False)
    assert len(first["alerts"]) == 50 and first["total"] == 120 and first["has_more"] is True
    last = await alerts_api.get_alerts(status="open", limit=50, offset=100, severity=None, agent=agent_id, session_id=None, since_hours=None, qualifying=False)
    assert len(last["alerts"]) == 20 and last["total"] == 120 and last["has_more"] is False
    ids = {a["id"] for a in first["alerts"]} | {a["id"] for a in last["alerts"]}
    assert len(ids) == 70


@pytest.mark.asyncio
async def test_the_qualifying_total_is_exact_and_not_capped_at_one_page(db):
    """The tray counts critical alerts and high red lines. 60 of them sit behind 80 newer low ones: the old tray request
    (first 50 rows, filtered in the tray) saw none of them."""
    agent_id = await _agent(db)
    await _alerts(db, agent_id, 60, "high", rule_type="red_line")
    await _alerts(db, agent_id, 5, "critical")
    await _alerts(db, agent_id, 30, "high")                # high but not a red line: does not qualify
    await db.execute("UPDATE alerts SET created_at = '2026-01-01 00:00:00' WHERE severity IN ('high', 'critical')")
    await db.commit()
    await _alerts(db, agent_id, 80, "low")                 # newer

    old_view = await alerts_api.get_alerts(status="open", limit=50, offset=0, severity=None, agent=agent_id, session_id=None, since_hours=None, qualifying=False)
    assert not any(a["severity"] in ("high", "critical") for a in old_view["alerts"])

    page = await alerts_api.get_alerts(status="open", limit=500, offset=0, severity=None, agent=agent_id, session_id=None, since_hours=None, qualifying=True)
    assert page["total"] == 65 and len(page["alerts"]) == 65
    assert all(a["severity"] == "critical" or "red_line" in a["rule_type"] for a in page["alerts"])

    small = await alerts_api.get_alerts(status="open", limit=10, offset=0, severity=None, agent=agent_id, session_id=None, since_hours=None, qualifying=True)
    assert len(small["alerts"]) == 10 and small["total"] == 65 and small["has_more"] is True
