"""Tests for core/mcp_service.py's _derive_friction_findings() retry_loop
detection, specifically Task 4 of the P1 pilot sprint: Vigil's own
footprint (its own backend process spawning, its own install/data paths)
must not be flagged as agent friction, while an ordinary repeated-call
pattern on a real project path must still be caught. See conftest.py for
why VLAW_DATA_DIR is set there rather than here -- this module must only
ever touch that isolated temp DB, never the real dev DB in backend/data/."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

import db.database as database
from core.mcp_service import _derive_friction_findings


@pytest_asyncio.fixture
async def test_db():
    """Same pattern as tests/test_bugfixes.py::test_db -- fresh connection
    per test, explicitly closed on teardown."""
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


async def _insert_retry_events(db, agent_id: int, session_id: str, event_type: str, path: str, count: int) -> None:
    """Inserts `count` events of the same type/path a minute apart, all
    well within the 10-minute retry_loop window."""
    base = datetime.now(timezone.utc)
    for i in range(count):
        ts = (base + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, ?, ?, ?)",
            (agent_id, session_id, event_type, path, ts),
        )
    await db.commit()


def _uniq(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_retry_loop_on_vigil_own_path_is_not_flagged(test_db):
    agent_id = await _make_agent(test_db, _uniq("claude_code_vigiltest"))
    session_id = _uniq("sess")

    await _insert_retry_events(
        test_db, agent_id, session_id, "proc_spawn",
        r"C:\Program Files\Vigil\backend\vigil-backend.exe", 5,
    )

    findings = await _derive_friction_findings(test_db, session_id=session_id)
    retry_findings = [f for f in findings if f["finding_type"] == "retry_loop"]
    assert retry_findings == []


@pytest.mark.asyncio
async def test_retry_loop_on_ordinary_project_path_is_still_flagged(test_db):
    agent_id = await _make_agent(test_db, _uniq("claude_code_realtest"))
    session_id = _uniq("sess")

    await _insert_retry_events(
        test_db, agent_id, session_id, "proc_spawn",
        r"C:\Users\dev\myproject\node_modules\.bin\cmd.exe", 5,
    )

    findings = await _derive_friction_findings(test_db, session_id=session_id)
    retry_findings = [f for f in findings if f["finding_type"] == "retry_loop"]
    assert len(retry_findings) == 1
    assert retry_findings[0]["confidence"] == "high"
    assert retry_findings[0]["session_id"] == session_id
