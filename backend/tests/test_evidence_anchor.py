"""Stage 1 evidence anchors (core/evidence_anchor.py): cadence, migration, the local check against anchors,
the export fields and the exact report wording. Every test uses its own database file and key directory;
none touches the shared test database."""

import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import api.export as export_module
import core.evidence_anchor as anchors
import core.evidence_chain as chain
import db.database as database
from core.evidence_chain import GENESIS_HASH, compute_row_hash, get_chain_head, seal_new_events, verify_chain

T0 = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
SCHEMA = Path(database.SCHEMA_PATH)


@pytest.fixture(autouse=True)
def _clean_cache():
    export_module._chain_cache["value"] = None
    yield
    export_module._chain_cache["value"] = None


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A fresh database (built from schema.sql) and a fresh key directory."""
    db_path = tmp_path / "vlaw.db"
    keys = tmp_path / "keys"
    monkeypatch.setattr(chain, "DB_PATH", db_path)
    monkeypatch.setenv("VLAW_KEY_DIR", str(keys))
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.read_text())
    conn.execute("INSERT INTO agents (name, process_name, approved) VALUES ('anchor_test_agent', 'x', 1)")
    conn.commit()
    conn.close()
    return types_ns(db_path=db_path, keys=keys)


def types_ns(**kw):
    import types

    return types.SimpleNamespace(**kw)


def sql(env, statement, params=()):
    conn = sqlite3.connect(env.db_path)
    try:
        cur = conn.execute(statement, params)
        conn.commit()
        return cur.fetchall()
    finally:
        conn.close()


def add_events(env, n, start=0):
    conn = sqlite3.connect(env.db_path)
    for i in range(start, start + n):
        conn.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (1, 'sess-a', 'file_write', ?, '2026-10-01 07:00:00')",
            (f"/tmp/f{i}.py",),
        )
    conn.commit()
    conn.close()


async def seal(env):
    while await seal_new_events():
        pass


async def make_chain(env, n=6):
    add_events(env, n)
    await seal(env)


def anchor_rows(env):
    return sql(env, "SELECT anchor_seq, trigger, event_count FROM evidence_anchors ORDER BY anchor_seq")


def recompute_chain(env):
    """What an attacker does after editing rows: rewrite every event_chain row with the same algorithm."""
    conn = sqlite3.connect(env.db_path)
    conn.row_factory = sqlite3.Row
    events = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM events")}
    prev = GENESIS_HASH
    for row in conn.execute("SELECT id, event_id FROM event_chain ORDER BY id").fetchall():
        new_hash = compute_row_hash(events[row["event_id"]], prev)
        conn.execute("UPDATE event_chain SET row_hash = ?, prev_hash = ? WHERE id = ?", (new_hash, prev, row["id"]))
        prev = new_hash
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ cadence

@pytest.mark.asyncio
async def test_hourly_anchor_is_made_once_per_hour_and_only_when_the_head_changed(env):
    await make_chain(env)
    first = await anchors.create_anchor("hourly", now=T0)
    assert first and first["anchor_seq"] == 1 and first["event_count"] == 6

    assert await anchors.create_anchor("hourly", now=T0 + timedelta(minutes=10)) is None, "not per call"
    assert await anchors.create_anchor("hourly", now=T0 + timedelta(hours=3)) is None, "head unchanged: no anchor"
    assert len(anchor_rows(env)) == 1

    add_events(env, 2, start=100)
    await seal(env)
    assert await anchors.create_anchor("hourly", now=T0 + timedelta(minutes=20)) is None, "changed, but under an hour"
    second = await anchors.create_anchor("hourly", now=T0 + timedelta(minutes=56))
    assert second and second["anchor_seq"] == 2 and second["event_count"] == 8
    assert second["prev_anchor_hash"] == first["anchor_hash"]
    assert [r[0] for r in anchor_rows(env)] == [1, 2]


@pytest.mark.asyncio
async def test_hourly_makes_no_anchor_on_an_empty_chain(env):
    assert await anchors.create_anchor("hourly", now=T0) is None
    assert anchor_rows(env) == []


@pytest.mark.asyncio
async def test_export_always_binds_to_an_anchor_but_reuses_one_that_already_pins_this_state(env):
    await make_chain(env)
    first = await anchors.create_anchor("export", now=T0)
    assert first["reused"] is False
    again = await anchors.create_anchor("export", now=T0 + timedelta(minutes=1))
    assert again["reused"] is True and again["anchor_seq"] == first["anchor_seq"], "a report preview must not pile up anchors"
    assert len(anchor_rows(env)) == 1

    sql(env, "INSERT INTO alerts (agent_id, severity, title, description) VALUES (1, 'low', 't', 'd')")
    changed = await anchors.create_anchor("export", now=T0 + timedelta(minutes=2))
    assert changed["reused"] is False and changed["anchor_seq"] == 2, "an alert the last anchor did not see: new anchor"


@pytest.mark.asyncio
async def test_a_restart_after_a_gap_is_always_pinned(env):
    await make_chain(env)
    await anchors.create_anchor("hourly", now=T0)
    pinned = await anchors.create_anchor("startup_gap", now=T0 + timedelta(minutes=5))
    assert pinned and pinned["anchor_seq"] == 2 and pinned["trigger"] == "startup_gap"


@pytest.mark.asyncio
async def test_creating_an_anchor_never_rehashes_the_chain(env, monkeypatch):
    await make_chain(env, 20)

    def boom(*args, **kwargs):
        raise AssertionError("the chain must not be re-hashed when an anchor is created")

    monkeypatch.setattr(chain, "compute_row_hash", boom)
    assert await anchors.create_anchor("export", now=T0)


@pytest.mark.asyncio
async def test_unknown_trigger_is_rejected(env):
    with pytest.raises(ValueError):
        await anchors.create_anchor("whenever")


# ------------------------------------------------------------------ migration

@pytest.mark.asyncio
async def test_an_existing_database_gains_the_table_without_losing_anything(tmp_path, monkeypatch):
    """A database from before this change has no evidence_anchors table. Starting the backend
    (init_db) adds it and leaves every existing row alone."""
    data = tmp_path / "data"
    data.mkdir()
    db_path = data / "vlaw.db"
    old_schema = SCHEMA.read_text()
    start = old_schema.index("-- Local evidence anchors")
    end = old_schema.index("CREATE INDEX IF NOT EXISTS idx_events_agent")
    conn = sqlite3.connect(db_path)
    conn.executescript(old_schema[:start] + old_schema[end:])
    conn.execute("INSERT INTO agents (name, process_name, approved) VALUES ('legacy', 'x', 1)")
    for i in range(5):
        conn.execute("INSERT INTO events (agent_id, session_id, event_type, path) VALUES (1, 's', 'file_write', ?)", (f"/p/{i}",))
    conn.commit()
    assert not conn.execute("SELECT name FROM sqlite_master WHERE name = 'evidence_anchors'").fetchall()
    before = conn.execute("SELECT id, path FROM events ORDER BY id").fetchall()
    conn.close()

    monkeypatch.setattr(database, "DATA_DIR", data)
    monkeypatch.setattr(database, "DB_PATH", db_path)
    monkeypatch.setattr(chain, "DB_PATH", db_path)
    monkeypatch.setenv("VLAW_KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(database, "_db", None)
    db = await database.init_db()
    try:
        cur = await db.execute("SELECT name FROM sqlite_master WHERE name = 'evidence_anchors'")
        assert await cur.fetchone() is not None
        cur = await db.execute("SELECT id, path FROM events ORDER BY id")
        assert [tuple(r) for r in await cur.fetchall()] == before
    finally:
        await database.close_db()
    await seal_new_events()
    assert await anchors.create_anchor("export", now=T0)
    assert (await verify_chain())["status"] == "consistent"


@pytest.mark.asyncio
async def test_an_empty_database_works(env):
    result = await verify_chain()
    assert result["valid"] is True and result["status"] == "consistent" and result["checked_count"] == 0
    assert result["anchors"]["status"] == "none" and result["anchors"]["anchoring"] == "none"
    db = await open_row_db(env)
    try:
        head = await get_chain_head(db)
    finally:
        await db.close()
    assert head["head_hash"] == GENESIS_HASH and head["sealed_count"] == 0 and head["last_anchor"] is None


async def open_row_db(env):
    return await anchors.connect(env.db_path)


# ------------------------------------------------------------------ what the check catches

@pytest.mark.asyncio
async def test_an_edit_without_recomputing_the_chain_is_caught(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    sql(env, "UPDATE events SET path = '/tmp/edited.py' WHERE id = 3")
    result = await verify_chain()
    assert result["valid"] is False and result["status"] == "inconsistent"
    assert result["reason"] == "hash_mismatch" and result["first_bad_event_id"] == 3


@pytest.mark.asyncio
async def test_tail_truncation_below_an_anchor_is_caught(env):
    await make_chain(env, 10)
    await anchors.create_anchor("export", now=T0)
    sql(env, "DELETE FROM event_chain WHERE event_id > 6")
    sql(env, "DELETE FROM events WHERE id > 6")
    result = await verify_chain()
    assert result["internally_consistent"] is True, "what is left is a perfect chain"
    assert result["valid"] is False and result["status"] == "shorter_than_local_anchor"
    problem = result["anchors"]["first_mismatch"]
    assert problem["kind"] == "shorter" and problem["anchor_seq"] == 1 and "recorded 10 sealed events" in problem["detail"]
    assert result["anchors"]["anchors_mismatched"] == 1


@pytest.mark.asyncio
async def test_deleting_a_middle_event_is_caught(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    sql(env, "DELETE FROM events WHERE id = 3")
    result = await verify_chain()
    assert result["valid"] is False and result["status"] == "inconsistent" and result["reason"] == "event_deleted"

    sql(env, "DELETE FROM event_chain WHERE event_id = 3")
    result = await verify_chain()
    assert result["valid"] is False and result["status"] == "inconsistent" and result["reason"] == "broken_link"


@pytest.mark.asyncio
async def test_edit_with_a_recomputed_chain_disagrees_with_the_local_anchor(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    sql(env, "UPDATE events SET path = '/tmp/rewritten.py' WHERE id = 2")
    recompute_chain(env)
    result = await verify_chain()
    assert result["internally_consistent"] is True, "Vigil's own walk is blind to a recomputed chain"
    assert result["valid"] is False and result["status"] == "disagrees_with_local_anchor"
    assert result["anchors"]["first_mismatch"]["kind"] == "disagrees"


@pytest.mark.asyncio
async def test_a_good_chain_with_anchors_is_consistent(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    add_events(env, 3, start=50)
    await seal(env)
    await anchors.create_anchor("startup_gap", now=T0 + timedelta(hours=2))
    result = await verify_chain()
    assert result["valid"] is True and result["status"] == "consistent"
    assert result["anchors"]["anchors_checked"] == 2 and result["anchors"]["anchors_mismatched"] == 0
    assert result["anchors"]["anchoring"] == "local_only" and result["anchors"]["continuity"]["status"] == "ok"


@pytest.mark.asyncio
async def test_an_edited_anchor_row_is_caught(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    sql(env, "UPDATE evidence_anchors SET event_count = 2 WHERE anchor_seq = 1")
    result = await verify_chain()
    assert result["valid"] is False and result["anchors"]["first_mismatch"]["kind"] == "altered"


@pytest.mark.asyncio
async def test_deleting_the_newest_anchors_is_a_continuity_break(env):
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    add_events(env, 2, start=70)
    await seal(env)
    await anchors.create_anchor("startup_gap", now=T0 + timedelta(hours=2))
    sql(env, "DELETE FROM evidence_anchors WHERE anchor_seq = 2")
    result = await verify_chain()
    assert result["status"] == "anchor_continuity_break" and result["anchors"]["continuity"]["kind"] == "series_restarted"


@pytest.mark.asyncio
async def test_deleting_vlaw_db_shows_as_a_series_restarted_state(env, tmp_path):
    """The key directory keeps the sequence counter, so a deleted or replaced database does not start a
    clean-looking series."""
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    add_events(env, 2, start=80)
    await seal(env)
    await anchors.create_anchor("startup_gap", now=T0 + timedelta(hours=2))

    env.db_path.unlink()
    conn = sqlite3.connect(env.db_path)
    conn.executescript(SCHEMA.read_text())
    conn.execute("INSERT INTO agents (name, process_name, approved) VALUES ('fresh', 'x', 1)")
    conn.commit()
    conn.close()

    fresh = await verify_chain()
    assert fresh["internally_consistent"] is True, "a brand-new chain is perfectly consistent on its own"
    assert fresh["valid"] is False and fresh["status"] == "anchor_continuity_break"
    assert fresh["anchors"]["continuity"]["kind"] == "series_restarted"
    assert "seq 2" in fresh["anchors"]["continuity"]["detail"]

    # The series carries on from the key directory's counter, so the missing history stays visible.
    add_events(env, 3)
    await seal(env)
    carried = await anchors.create_anchor("export", now=T0 + timedelta(hours=3))
    assert carried["anchor_seq"] == 3
    after = await verify_chain()
    assert after["status"] == "anchor_continuity_break" and after["anchors"]["continuity"]["kind"] == "history_missing"


@pytest.mark.asyncio
async def test_forgetting_the_key_directory_gives_the_rewrite_away(env):
    """An attacker who recomputes the chain and rewrites the anchors table but leaves the key directory's
    record of the last anchor alone is caught: the hash it recorded no longer matches."""
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    sql(env, "UPDATE events SET path = '/tmp/x.py' WHERE id = 2")
    recompute_chain(env)
    rewrite_anchors(env, update_state=False)
    result = await verify_chain()
    assert result["valid"] is False and result["status"] == "anchor_continuity_break"
    assert "differs from the hash the key directory recorded" in result["anchors"]["continuity"]["detail"]


def rewrite_anchors(env, update_state):
    """The attacker's script: rebuild every stored anchor so it matches the rewritten chain, relink them, and
    (optionally) update the key directory's record to match."""
    conn = sqlite3.connect(env.db_path)
    conn.row_factory = sqlite3.Row
    old = conn.execute("SELECT * FROM evidence_anchors ORDER BY anchor_seq").fetchall()
    prev = GENESIS_HASH
    last = None
    for row in old:
        head = conn.execute("SELECT row_hash FROM event_chain WHERE event_id = ?", (row["last_event_id"],)).fetchone()["row_hash"]
        fields = json.loads(row["anchor_json"])
        fields.update(chain_head=head, prev_anchor_hash=prev)
        text = anchors.canonical_json(fields)
        new_hash = anchors.anchor_hash_of(text)
        conn.execute(
            "UPDATE evidence_anchors SET anchor_json = ?, anchor_hash = ?, prev_anchor_hash = ?, chain_head = ? WHERE anchor_seq = ?",
            (text, new_hash, prev, head, row["anchor_seq"]),
        )
        prev, last = new_hash, (row["anchor_seq"], head)
    conn.commit()
    conn.close()
    if update_state:
        state = anchors.load_state(env.keys)
        state["last_anchor_hash"] = prev
        state["last_chain_head"] = last[1]
        anchors.save_state(state, env.keys)


@pytest.mark.asyncio
async def test_stage1_does_not_constrain_attacker_who_rewrites_anchors(env):
    """THE LIMIT OF STAGE 1, documented as a test. Local anchors live in the database and the key directory,
    both writable by the account that runs the monitored agent. Someone who edits events, recomputes the
    chain, rebuilds the anchors table AND updates the key directory record leaves nothing for Vigil's own
    check to find: it reports a consistent chain, and the report still says there is no external anchor.
    Only an anchor held outside the machine (Stage 2, an external timestamp) constrains this attacker."""
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    add_events(env, 2, start=60)
    await seal(env)
    await anchors.create_anchor("startup_gap", now=T0 + timedelta(hours=2))
    assert (await verify_chain())["status"] == "consistent"

    sql(env, "UPDATE events SET path = '/tmp/forged.py', detail = '{\"forged\": true}' WHERE id IN (2, 4)")
    sql(env, "DELETE FROM alerts")
    recompute_chain(env)
    rewrite_anchors(env, update_state=True)

    result = await verify_chain()
    assert result["valid"] is True and result["status"] == "consistent", "not caught: this is the documented limit"
    assert result["anchors"]["anchors_mismatched"] == 0 and result["anchors"]["continuity"]["status"] == "ok"
    lines = export_module._chain_lines(await export_module._chain_verification())
    assert export_module.NO_ANCHORING_LINE in lines, "and the report still says the chain is stored only on this machine"


# ------------------------------------------------------------------ exports

@pytest.mark.asyncio
async def test_json_export_fields(env):
    await make_chain(env, 4)
    verification = await export_module._chain_verification()
    for key in ("head_hash", "sealed_count", "unsealed_count", "last_anchor", "anchors_checked", "anchors_mismatched",
                "status", "events_checked", "scope", "anchoring", "anchor_continuity"):
        assert key in verification, key
    assert verification["status"] == "consistent" and verification["sealed_count"] == 4 and verification["unsealed_count"] == 0
    assert verification["anchors_checked"] == 1 and verification["anchors_mismatched"] == 0
    last = verification["last_anchor"]
    assert set(last) >= {"time", "anchor_seq", "position", "head"} and last["anchor_seq"] == 1 and last["position"] == 4
    assert last["head"] == verification["head_hash"]
    json.dumps(verification)


@pytest.mark.asyncio
async def test_a_brand_new_database_never_reports_zero_mismatches_as_a_pass(env, monkeypatch):
    async def no_anchor(*args, **kwargs):
        return None

    monkeypatch.setattr(anchors, "create_anchor", no_anchor)
    verification = await export_module._chain_verification()
    assert verification["anchors_checked"] == 0 and verification["anchors_mismatched"] is None
    lines = export_module._chain_lines(verification)
    assert lines == [
        f"Evidence chain: consistent, 0 events, head {GENESIS_HASH[:12]}",
        "Anchoring: none. The chain is consistent but is stored only on this machine; this report cannot show that earlier records were not altered.",
    ]
    assert not any("mismatch" in line for line in lines)


def _base(**over):
    chain_state = {
        "status": "consistent", "events_checked": 120, "first_bad_event_id": None, "detail": None,
        "head_hash": "abcdef0123456789" + "0" * 48, "sealed_count": 120, "unsealed_count": 0, "anchoring": "local_only",
        "last_anchor": {"time": "2026-10-10T09:00:00Z", "anchor_seq": 17, "position": 120, "head": "abcdef0123456789", "status": "local_only"},
        "anchors_checked": 17, "anchors_mismatched": 0, "anchor_continuity": {"status": "ok", "kind": None, "detail": None},
        "anchor_problem": None,
    }
    chain_state.update(over)
    return chain_state


def test_report_wording_for_every_state():
    expect_none = "Anchoring: none. The chain is consistent but is stored only on this machine; this report cannot show that earlier records were not altered."

    assert export_module._chain_lines(_base()) == [
        "Evidence chain: consistent, 120 events, head abcdef012345",
        "Local anchors: 17 recorded, last 2026-10-10T09:00:00Z (seq 17), status: local only, no external timestamp. 17 of 17 match the chain. Checked by Vigil itself.",
        expect_none,
    ]
    assert export_module._chain_lines(_base(unsealed_count=3))[-1] == "Not yet sealed into the chain: 3 events (sealed within about 15 seconds)."

    inconsistent = _base(status="inconsistent", first_bad_event_id=42)
    assert export_module._chain_lines(inconsistent) == ["Evidence chain: INCONSISTENT at event 42. Do not rely on this report."]

    disagrees = export_module._chain_lines(_base(
        status="disagrees_with_local_anchor", anchors_mismatched=1,
        anchor_problem={"anchor_seq": 12, "kind": "disagrees", "detail": "the chain has a different hash at event 99 than anchor 12 recorded"}))
    assert disagrees[0] == "Evidence chain: consistent, but it DISAGREES with local anchor seq 12. Do not rely on this report."
    assert expect_none not in disagrees and "16 of 17 match the chain" in disagrees[2]

    shorter = export_module._chain_lines(_base(
        status="shorter_than_local_anchor", anchors_mismatched=1,
        anchor_problem={"anchor_seq": 17, "kind": "shorter", "detail": "anchor 17 recorded 120 sealed events (last event 130), the chain has 80 (last event 90)"}))
    assert shorter[0] == "Evidence chain: SHORTER than local anchor seq 17. Records may have been removed. Do not rely on this report."
    assert expect_none not in shorter

    broke = export_module._chain_lines(_base(
        status="anchor_continuity_break",
        anchor_continuity={"status": "break", "kind": "link_broken", "detail": "BREAK between seq 12 and seq 14"}))
    assert broke[0] == "Evidence chain: consistent, 120 events, head abcdef012345"
    assert broke[1] == "Anchor continuity: BREAK. BREAK between seq 12 and seq 14 Do not rely on this report."
    assert expect_none in broke


def test_no_report_state_uses_words_the_design_forbids():
    forbidden = ("tamper", "cannot be altered", "verified by", "immutable", "cryptographically verified", "audit-grade")
    states = [
        _base(), _base(unsealed_count=2), _base(status="inconsistent", first_bad_event_id=1),
        _base(status="disagrees_with_local_anchor", anchor_problem={"anchor_seq": 1, "kind": "disagrees", "detail": "x"}),
        _base(status="shorter_than_local_anchor", anchor_problem={"anchor_seq": 1, "kind": "shorter", "detail": "x"}),
        _base(status="anchor_continuity_break", anchor_continuity={"status": "break", "kind": "series_restarted", "detail": "x"}),
        _base(anchors_checked=0, anchors_mismatched=None, last_anchor=None, anchoring="none"),
    ]
    text = " ".join(" ".join(export_module._chain_lines(s)) for s in states) + " " + export_module.CHAIN_SCOPE + export_module.NO_ANCHORING_LINE
    for word in forbidden:
        assert word not in text.lower(), word


@pytest.mark.asyncio
async def test_pdf_header_lines_are_drawn_exactly(env):
    """The PDF draws _chain_lines() through the same wrapping as every other line; the text captured from
    the real PDF export contains each line (wrapped lines rejoin with single spaces)."""
    from unittest.mock import patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from reportlab.pdfgen import canvas

    await make_chain(env, 5)

    async def fake_build_summary(date, tz=None):
        return {
            "date": "2026-03-15", "generated_at": "2026-03-15T12:00:00+00:00",
            "period_start": "2026-03-15T00:00:00+00:00", "period_end": "2026-03-16T00:00:00+00:00",
            "timezone": "UTC", "event_count": 0, "sessions": [], "alerts": [],
            "report_notes": export_module.REPORT_NOTES, "coverage_available": False, "tracking_started_at": None,
            "active_seconds": 0, "period_seconds_measured": 0, "gaps": [], "short_gap_count": 0, "short_gap_seconds": 0,
        }

    drawn = []
    original = canvas.Canvas.drawString
    app = FastAPI()
    app.include_router(export_module.router)
    with patch.object(export_module, "_build_summary", fake_build_summary), \
         patch.object(canvas.Canvas, "drawString", lambda self, x, y, t: (drawn.append(t), original(self, x, y, t))[1]):
        assert TestClient(app).get("/export/pdf").status_code == 200
    text = " ".join(drawn)
    sealed = await verify_chain()
    verification = await export_module._chain_verification()
    for line in export_module._chain_lines(verification):
        assert line in text, line
    assert f"head {verification['head_hash'][:12]}" in text and sealed["valid"] is True


@pytest.mark.asyncio
async def test_head_endpoint_carries_the_last_anchor(env):
    await make_chain(env, 3)
    await anchors.create_anchor("export", now=T0)
    db = await anchors.connect(env.db_path)
    try:
        head = await get_chain_head(db)
    finally:
        await db.close()
    assert head["anchoring"] == "local_only"
    last = head["last_anchor"]
    assert last["anchor_seq"] == 1 and last["position"] == 3 and last["time"] == "2026-10-01T08:00:00Z"
    assert last["head"] == head["head_hash"] and head["sealed_count"] == 3 and head["unsealed_count"] == 0


# ------------------------------------------------------------------ the anchor itself

@pytest.mark.asyncio
async def test_anchor_hash_is_the_sha256_of_the_canonical_json_and_the_key_directory_keeps_the_counter(env):
    await make_chain(env)
    first = await anchors.create_anchor("export", now=T0)
    row = sql(env, "SELECT anchor_json, anchor_hash, prev_anchor_hash, install_id, tables_digest FROM evidence_anchors WHERE anchor_seq = 1")[0]
    assert hashlib.sha256(row[0].encode()).hexdigest() == row[1] == first["anchor_hash"]
    assert row[2] == GENESIS_HASH and len(row[4]) == 64
    fields = json.loads(row[0])
    assert list(fields) == sorted(fields), "canonical: sorted keys"
    assert set(fields) == {"v", "install_id", "anchor_seq", "prev_anchor_hash", "chain_head", "event_count",
                           "last_event_id", "meta_head", "tables_digest", "created_at"}
    state = anchors.load_state(env.keys)
    assert state["install_id"] == row[3] and state["anchor_seq"] == 1 and state["last_anchor_hash"] == row[1]
    assert not str(env.keys).startswith(str(env.db_path.parent / "data")), "the key directory is not the data directory"


@pytest.mark.asyncio
async def test_the_tables_digest_follows_the_covered_tables(env):
    await make_chain(env)
    first = await anchors.create_anchor("export", now=T0)
    for statement in (
        "INSERT INTO alerts (agent_id, severity, title, description) VALUES (1, 'low', 't', 'd')",
        "INSERT INTO audit_log (action, entity_type, entity_id, actor) VALUES ('x', 'agent', '1', 'me')",
        "INSERT INTO sessions (id, agent_id) VALUES ('s-new', 1)",
        "INSERT INTO monitoring_gaps (run_id, gap_start, gap_end, reason) VALUES ('r', '2026-10-01 00:00:00', '2026-10-01 00:01:00', 'x')",
        "INSERT INTO policy (policy_key, policy_value) VALUES ('k', 'v')",
    ):
        before = (await anchors.create_anchor("export", now=T0 + timedelta(hours=1)))["tables_digest"]
        sql(env, statement)
        after = (await anchors.create_anchor("export", now=T0 + timedelta(hours=2)))["tables_digest"]
        assert after != before, statement
    assert first["tables_digest"] != after


# ------------------------------------------------------------------ key directory lifecycle

@pytest.mark.asyncio
async def test_a_new_database_with_events_and_no_key_directory_starts_a_clean_series(env):
    """A fresh install after a deliberate wipe (the uninstaller deleted the whole V-LAW folder, key
    directory included), or any database whose key directory does not exist yet."""
    assert not env.keys.exists()
    await make_chain(env, 8)
    before = await verify_chain()
    assert before["valid"] is True and before["status"] == "consistent"
    assert before["anchors"]["status"] == "none" and before["anchors"]["continuity"]["status"] == "none"

    verification = await export_module._chain_verification()
    assert verification["status"] == "consistent" and verification["anchors_checked"] == 1
    assert verification["anchor_continuity"]["status"] == "ok"
    lines = " ".join(export_module._chain_lines(verification))
    assert "BREAK" not in lines and "Do not rely" not in lines and "DISAGREES" not in lines
    state = anchors.load_state(env.keys)
    assert state["anchor_seq"] == 1 and "pending_seq" not in state


@pytest.mark.asyncio
async def test_an_upgrade_from_a_pre_anchor_version_shows_anchoring_none_and_flags_nothing(env):
    """Events and a sealed chain exist, there are no anchors and no key directory (an install from before
    Stage 1). Nothing is flagged; the report says there is no anchoring."""
    await make_chain(env, 12)
    assert anchor_rows(env) == [] and not env.keys.exists()

    cached = await export_module.refresh_chain_verification_cache()
    assert cached["status"] == "consistent" and cached["anchors_checked"] == 0 and cached["anchors_mismatched"] is None
    assert cached["anchoring"] == "none" and cached["anchor_continuity"]["status"] == "none"
    lines = export_module._chain_lines(cached)
    assert lines == [
        f"Evidence chain: consistent, 12 events, head {cached['head_hash'][:12]}",
        export_module.NO_ANCHORING_LINE,
    ]
    assert not env.keys.exists(), "checking creates nothing"


@pytest.mark.asyncio
async def test_a_deleted_database_with_a_surviving_key_directory_is_reported_by_design(env):
    """The other half of the lifecycle: the database alone was deleted. That is a series restart, by design."""
    await make_chain(env)
    await anchors.create_anchor("export", now=T0)
    env.db_path.unlink()
    conn = sqlite3.connect(env.db_path)
    conn.executescript(SCHEMA.read_text())
    conn.close()
    result = await verify_chain()
    assert result["status"] == "anchor_continuity_break" and result["anchors"]["continuity"]["kind"] == "series_restarted"
    # A legitimate reset removes the key directory as well (the uninstaller's "delete everything" does).
    shutil.rmtree(env.keys)
    assert (await verify_chain())["status"] == "consistent"


# ------------------------------------------------------------------ reuse of the last anchor

@pytest.mark.asyncio
async def test_reuse_compares_the_freshly_computed_digest_head_and_count(env, monkeypatch):
    await make_chain(env)
    first = await anchors.create_anchor("export", now=T0)

    calls = []
    real = anchors.tables_digest

    async def spy(conn):
        value = await real(conn)
        calls.append(value)
        return value

    monkeypatch.setattr(anchors, "tables_digest", spy)
    same = await anchors.create_anchor("export", now=T0 + timedelta(minutes=1))
    assert same["reused"] is True and calls, "the digest is recomputed on every export, never skipped"

    async def different(conn):
        return "f" * 64

    monkeypatch.setattr(anchors, "tables_digest", different)
    changed = await anchors.create_anchor("export", now=T0 + timedelta(minutes=2))
    assert changed["reused"] is False and changed["anchor_seq"] == first["anchor_seq"] + 1, "same head and count, different digest"


@pytest.mark.asyncio
async def test_dismissing_an_alert_in_place_makes_the_next_export_record_a_new_anchor(env):
    sql(env, "INSERT INTO alerts (agent_id, severity, title, description, status) VALUES (1, 'high', 'a', 'd', 'open')")
    await make_chain(env)
    first = await anchors.create_anchor("export", now=T0)
    assert (await anchors.create_anchor("export", now=T0 + timedelta(minutes=1)))["reused"] is True

    sql(env, "UPDATE alerts SET status = 'dismissed', resolved_by = 'me', resolved_at = '2026-10-01 09:00:00' WHERE id = 1")
    after = await anchors.create_anchor("export", now=T0 + timedelta(minutes=2))
    assert after["reused"] is False and after["anchor_seq"] == first["anchor_seq"] + 1
    assert after["tables_digest"] != first["tables_digest"]
    assert after["event_count"] == first["event_count"] and after["chain_head"] == first["chain_head"], "the chain itself did not change"


# ------------------------------------------------------------------ crash windows

class Crash(Exception):
    pass


def crash_at(monkeypatch, point):
    def raiser(name):
        if name == point:
            raise Crash(name)

    monkeypatch.setattr(anchors, "_crash_point", raiser)


def seqs(env):
    return [r[0] for r in anchor_rows(env)]


async def _prepare(env, existing_anchors):
    await make_chain(env)
    for i in range(existing_anchors):
        add_events(env, 1, start=200 + i)
        await seal(env)
        await anchors.create_anchor("export", now=T0 + timedelta(hours=i))
    return seqs(env)


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_anchors", [0, 2])
async def test_crash_after_the_key_directory_write_before_the_insert(env, monkeypatch, existing_anchors):
    before = await _prepare(env, existing_anchors)

    add_events(env, 1, start=300)
    await seal(env)
    crash_at(monkeypatch, "state_pending_written")
    assert await anchors.create_anchor("export", now=T0 + timedelta(hours=5)) is None
    assert seqs(env) == before, "no row was inserted"
    state = anchors.load_state(env.keys)
    assert state["pending_seq"] == len(before) + 1, "the key directory remembers the anchor it was about to add"
    assert state["anchor_seq"] == len(before)

    honest = await verify_chain()
    assert honest["valid"] is True and honest["status"] == "consistent", "an honest crash is not tampering"
    assert honest["anchors"]["continuity"]["status"] in ("ok", "none")

    monkeypatch.setattr(anchors, "_crash_point", lambda name: None)
    nxt = await anchors.create_anchor("export", now=T0 + timedelta(hours=6))
    assert nxt["anchor_seq"] == len(before) + 1 and seqs(env) == before + [len(before) + 1]
    assert len(set(seqs(env))) == len(seqs(env)) and seqs(env) == sorted(seqs(env))
    assert (await verify_chain())["status"] == "consistent"
    assert "pending_seq" not in anchors.load_state(env.keys)


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_anchors", [0, 2])
async def test_crash_after_the_insert_before_the_key_directory_advances(env, monkeypatch, existing_anchors):
    before = await _prepare(env, existing_anchors)

    add_events(env, 1, start=300)
    await seal(env)
    crash_at(monkeypatch, "anchor_committed")
    assert await anchors.create_anchor("export", now=T0 + timedelta(hours=5)) is None
    assert seqs(env) == before + [len(before) + 1], "the row did commit"
    state = anchors.load_state(env.keys)
    assert state["anchor_seq"] == len(before) and state["pending_seq"] == len(before) + 1, "the key directory is one anchor behind"

    honest = await verify_chain()
    assert honest["valid"] is True and honest["status"] == "consistent", "the database being one ahead is an honest crash"
    assert honest["anchors"]["continuity"]["status"] == "ok" and honest["anchors"]["anchors_mismatched"] == 0

    monkeypatch.setattr(anchors, "_crash_point", lambda name: None)
    add_events(env, 1, start=400)
    await seal(env)
    nxt = await anchors.create_anchor("export", now=T0 + timedelta(hours=6))
    assert nxt["anchor_seq"] == len(before) + 2 and len(set(seqs(env))) == len(seqs(env)) and seqs(env) == sorted(seqs(env))
    assert (await verify_chain())["status"] == "consistent"
    assert anchors.load_state(env.keys)["anchor_seq"] == len(before) + 2


# ------------------------------------------------------------------ page loads versus downloads

@pytest.mark.asyncio
async def test_a_preview_seals_digests_and_anchors_nothing(env, monkeypatch):
    await make_chain(env, 5)

    async def forbidden(*args, **kwargs):
        raise AssertionError("a page load must not seal, digest or record an anchor")

    monkeypatch.setattr(chain, "seal_new_events", forbidden)
    monkeypatch.setattr(anchors, "create_anchor", forbidden)
    monkeypatch.setattr(anchors, "tables_digest", forbidden)
    monkeypatch.setattr(chain, "verify_chain", forbidden)

    first = await export_module._chain_verification(fresh=False)
    assert first["status"] == "not_checked"
    assert first["as_of"] is None and "Download the report" in first["note"]
    assert first["sealed_count"] == 5 and first["head_hash"] != GENESIS_HASH
    assert export_module._chain_lines(first) == ["Evidence chain: not checked in this view. Download the report to run the check."]
    assert anchor_rows(env) == []


@pytest.mark.asyncio
async def test_a_preview_returns_the_last_check_with_its_time(env):
    await make_chain(env, 5)
    download = await export_module._chain_verification(fresh=True)
    assert download["status"] == "consistent" and download["as_of"] and download["cached"] is False
    rows_after_download = anchor_rows(env)

    add_events(env, 3, start=500)       # events arrive after the download
    preview = await export_module._chain_verification(fresh=False)
    assert preview["cached"] is True and preview["as_of"] == download["as_of"]
    assert preview["status"] == "consistent" and preview["head_hash"] == download["head_hash"]
    assert anchor_rows(env) == rows_after_download


@pytest.mark.asyncio
async def test_export_json_preview_flag_and_the_default(env, monkeypatch):
    await make_chain(env, 4)

    async def fake_summary(date, tz=None):
        return {"date": "x", "event_count": 0, "sessions": [], "alerts": []}

    monkeypatch.setattr(export_module, "_build_summary", fake_summary)
    preview = await export_module.export_json(date="today", preview=True)
    assert preview["chain_verification"]["status"] == "not_checked" and anchor_rows(env) == []
    download = await export_module.export_json(date="today", preview=False)
    assert download["chain_verification"]["status"] == "consistent" and len(anchor_rows(env)) == 1
    again = await export_module.export_json(date="today", preview=True)
    assert again["chain_verification"]["cached"] is True and again["chain_verification"]["as_of"] == download["chain_verification"]["as_of"]


def test_the_export_page_previews_and_only_the_download_link_runs_the_check():
    root = Path(__file__).resolve().parents[2] / "frontend" / "src"
    api_js = (root / "api.js").read_text(encoding="utf-8")
    page = (root / "components" / "Export.jsx").read_text(encoding="utf-8")
    assert "preview=true" in api_js and "exportJsonPreviewUrl" in api_js
    assert "fetch(api.exportJsonPreviewUrl(date))" in page
    assert "href={problem ? undefined : api.exportJsonUrl(date)}" in page, "the download link has no preview flag"
