"""Tests for core/evidence_chain.py's hash-chained tamper-evidence over
the events table, plus core/sessions.py's touch() capturing operator
identity (core/identity.py). See conftest.py for why VLAW_DATA_DIR is set
there rather than here -- this module must only ever touch that isolated
temp DB, never the real dev DB in backend/data/."""

import uuid

import pytest
import pytest_asyncio

import db.database as database
from db.database import get_db

from core.evidence_chain import GENESIS_HASH, get_chain_head, seal_new_events, verify_chain
from core.sessions import SessionManager


# ---------------------------------------------------------------- fixtures

@pytest_asyncio.fixture
async def test_db():
    """Same pattern as tests/test_bugfixes.py::test_db -- fresh connection
    per test, explicitly closed on teardown (aiosqlite.Connection is a
    non-daemon background Thread; leaving it open leaks a thread per test
    and is what previously hung CI)."""
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


async def _insert_event(db, agent_id: int, session_id: str, path: str) -> int:
    cur = await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'file_write', ?)",
        (agent_id, session_id, path),
    )
    await db.commit()
    return cur.lastrowid


def _uniq(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:8]}"


# ------------------------------------------------------------- 1. empty db

@pytest.mark.asyncio
async def test_seal_and_verify_empty(test_db):
    result = await verify_chain(test_db)
    assert result == {"valid": True, "checked_count": 0, "reason": None, "detail": None}


# -------------------------------------------------------- 2. seal creates chain

@pytest.mark.asyncio
async def test_seal_creates_chain(test_db):
    """seal_new_events() sweeps every unsealed row in the whole events
    table, not just rows from this test -- the shared persistent test DB
    (see conftest.py) means earlier test files/tests may have left their
    own events unsealed. Asserted as a delta against the pre-test
    unsealed count, not a hardcoded absolute, so this isn't sensitive to
    what ran before it."""
    unsealed_before = (await get_chain_head(test_db))["unsealed_count"]

    agent_id = await _make_agent(test_db, _uniq("claude_code_sealtest"))
    session_id = _uniq("sess")

    for i in range(3):
        await _insert_event(test_db, agent_id, session_id, f"/tmp/file{i}.py")

    sealed = await seal_new_events(test_db)
    assert sealed == unsealed_before + 3

    cur = await test_db.execute("SELECT COUNT(*) c FROM event_chain")
    assert (await cur.fetchone())["c"] == sealed

    head = await get_chain_head(test_db)
    assert head["sealed_count"] == sealed
    assert head["unsealed_count"] == 0
    assert head["head_hash"] != GENESIS_HASH

    result = await verify_chain(test_db)
    assert result["valid"] is True
    assert result["checked_count"] == sealed


# --------------------------------------------------- 3. tampering detection

@pytest.mark.asyncio
async def test_verify_detects_tampering(test_db):
    """verify_chain() walks the whole chain from genesis and returns on
    the FIRST problem found. The test DB file persists across this whole
    test run (see conftest.py), so a corruption left behind here would
    make every later test's verify_chain() call report THIS row forever
    instead of whatever it's actually testing -- the tampering is
    reverted at the end so the chain is valid again for subsequent
    tests, same reasoning as test_verify_detects_deletion below."""
    agent_id = await _make_agent(test_db, _uniq("claude_code_tampertest"))
    session_id = _uniq("sess")

    event_id = await _insert_event(test_db, agent_id, session_id, "/tmp/original.py")
    await _insert_event(test_db, agent_id, session_id, "/tmp/other.py")

    await seal_new_events(test_db)

    await test_db.execute("UPDATE events SET path = ? WHERE id = ?", ("/tmp/tampered.py", event_id))
    await test_db.commit()

    try:
        result = await verify_chain(test_db)
        assert result["valid"] is False
        assert result["reason"] == "hash_mismatch"
    finally:
        await test_db.execute("UPDATE events SET path = ? WHERE id = ?", ("/tmp/original.py", event_id))
        await test_db.commit()


# ---------------------------------------------------- 4. deletion detection

@pytest.mark.asyncio
async def test_verify_detects_deletion(test_db):
    """Same cross-test-pollution reasoning as test_verify_detects_tampering
    above -- the deleted row is re-inserted with its original id and
    field values afterward so later tests' verify_chain() calls see a
    valid chain again, not this test's leftover corruption."""
    agent_id = await _make_agent(test_db, _uniq("claude_code_deletetest"))
    session_id = _uniq("sess")

    event_id = await _insert_event(test_db, agent_id, session_id, "/tmp/doomed.py")
    await _insert_event(test_db, agent_id, session_id, "/tmp/survivor.py")

    await seal_new_events(test_db)

    cur = await test_db.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    original_row = dict(await cur.fetchone())

    # events.id is referenced by event_chain.event_id with FK enforcement on
    # (PRAGMA foreign_keys = ON, see db/database.py) and no ON DELETE action,
    # so deleting a sealed event through this same connection would raise
    # IntegrityError rather than exercise verify_chain()'s detection path.
    # A real tamperer editing the DB file directly (not through this app's
    # connection) wouldn't be bound by that PRAGMA either, so toggling it
    # off for just this delete simulates that more realistically than it
    # dodges the constraint.
    await test_db.execute("PRAGMA foreign_keys = OFF")
    await test_db.execute("DELETE FROM events WHERE id = ?", (event_id,))
    await test_db.commit()

    try:
        result = await verify_chain(test_db)
        assert result["valid"] is False
        assert result["reason"] == "event_deleted"
    finally:
        columns = list(original_row.keys())
        placeholders = ", ".join("?" * len(columns))
        await test_db.execute(
            f"INSERT INTO events ({', '.join(columns)}) VALUES ({placeholders})",
            [original_row[c] for c in columns],
        )
        await test_db.commit()
        await test_db.execute("PRAGMA foreign_keys = ON")


# ------------------------------------------------- 5. persists across calls

@pytest.mark.asyncio
async def test_chain_persists_across_seal_calls(test_db):
    """Delta-based (see test_seal_creates_chain) since seal_new_events()
    sweeps the whole table, not just this test's own rows."""
    unsealed_before = (await get_chain_head(test_db))["unsealed_count"]

    agent_id = await _make_agent(test_db, _uniq("claude_code_persisttest"))
    session_id = _uniq("sess")

    await _insert_event(test_db, agent_id, session_id, "/tmp/first.py")
    await _insert_event(test_db, agent_id, session_id, "/tmp/second.py")

    first_sealed = await seal_new_events(test_db)
    assert first_sealed == unsealed_before + 2

    head_after_first = await get_chain_head(test_db)

    await _insert_event(test_db, agent_id, session_id, "/tmp/third.py")
    await _insert_event(test_db, agent_id, session_id, "/tmp/fourth.py")

    second_sealed = await seal_new_events(test_db)
    assert second_sealed == 2

    cur = await test_db.execute("SELECT id, event_id, prev_hash, row_hash FROM event_chain ORDER BY id ASC")
    rows = await cur.fetchall()
    assert len(rows) == head_after_first["sealed_count"] + 2

    # The second seal call's first row must chain onto the first call's
    # last row, not restart from GENESIS_HASH.
    assert rows[-2]["prev_hash"] == head_after_first["head_hash"]

    result = await verify_chain(test_db)
    assert result["valid"] is True
    assert result["checked_count"] == head_after_first["sealed_count"] + 2


# ------------------------------------------------ 6. operator identity capture

@pytest.mark.asyncio
async def test_session_captures_operator_identity(test_db, monkeypatch):
    monkeypatch.setattr(
        "core.identity.get_operator_identity",
        lambda: ("testuser", "testhost"),
    )

    agent_id = await _make_agent(test_db, _uniq("claude_code_identitytest"))

    sm = SessionManager()
    session_id = await sm.touch(agent_id)

    cur = await test_db.execute(
        "SELECT operator_username, operator_hostname FROM sessions WHERE id = ?", (session_id,)
    )
    row = await cur.fetchone()
    assert row["operator_username"] == "testuser"
    assert row["operator_hostname"] == "testhost"
