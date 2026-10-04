"""Append-only hash chain over the events table. Additive only — never
modifies events or any existing insert path (see core/evidence.py's
Model B docstring for the precedent on this pattern). A periodic job
(see main.py) seals newly-written events into event_chain, each row's
hash computed over its own canonical fields plus the previous chain
row's hash — so altering, reordering, or deleting any already-sealed
event is detectable by verify_chain(), even though this module never
stops such an edit from happening at the SQLite level.

GENESIS_HASH is the prev_hash for the very first event ever sealed —
an arbitrary, fixed 64-char placeholder (not a real hash of anything),
documented so verify_chain() can recognize and accept it rather than
treating the first row as a broken link.
"""

import hashlib
import logging

import aiosqlite
from db.database import DB_PATH

GENESIS_HASH = "0" * 64

# Caps how many backlogged events a single seal_new_events() call will seal.
# Without this, a backlog (e.g. after a burst of activity, or after this job
# itself falls behind) gets sealed in one unbounded loop -- observed taking
# 54s for ~14k backlogged rows, during which every other caller sharing the
# connection it ran on queued behind it. Capping the batch means a large
# backlog drains incrementally across multiple 15s scheduler cycles instead
# of blocking everything in one long run; the next cycle simply picks up
# wherever this one left off (ORDER BY id ASC, resumed from MAX(event_id)).
SEAL_BATCH_LIMIT = 500


def _canonical_row_string(event_row: dict) -> str:
    """Deterministic string representation of one events row, fields in
    a fixed order, every field coerced to str() with None -> "". Order
    and field set must never change once any chain exists in production
    -- changing it would make every already-sealed row unverifiable
    against newly computed hashes. Deliberately excludes nothing: every
    column that could be tampered with must be represented."""
    fields = [
        event_row.get("id"), event_row.get("agent_id"), event_row.get("session_id"),
        event_row.get("event_type"), event_row.get("path"), event_row.get("detail"),
        event_row.get("file_count"), event_row.get("data_volume_bytes"),
        event_row.get("severity"), event_row.get("anomaly_score"), event_row.get("pid"),
        event_row.get("behaviour_score"), event_row.get("event_source"),
        event_row.get("created_at"),
    ]
    return "|".join("" if f is None else str(f) for f in fields)


def compute_row_hash(event_row: dict, prev_hash: str) -> str:
    return hashlib.sha256((prev_hash + _canonical_row_string(event_row)).encode("utf-8")).hexdigest()


async def seal_new_events() -> int:
    """Called periodically (every 15s, see main.py's scheduler). Finds up
    to SEAL_BATCH_LIMIT events rows not yet in event_chain, in ascending
    id order, and seals each one in turn. Returns how many rows were
    sealed this call -- a return equal to SEAL_BATCH_LIMIT signals there
    may be more backlog left for the next cycle to pick up.

    Runs on its own dedicated connection, deliberately not the shared
    get_db() singleton -- same reasoning as Aggregator._checkpoint():
    this used to run on get_db() and, measured directly, a 14k-row
    backlog took 54s to seal on that shared connection, during which
    every other caller of get_db() (including plain health checks)
    queued behind it since aiosqlite serializes all operations on a
    connection through one background thread. A dedicated connection
    plus the batch cap above means neither problem can recur: this job
    can never block any other caller, and no single run can take longer
    than SEAL_BATCH_LIMIT rows' worth of work regardless of connection.

    Must never raise -- scheduler jobs that raise get logged loudly by
    APScheduler but this must not take anything else down with it, so
    the body is wrapped in try/except, logging and returning 0 on
    failure, matching the pattern in core/sessions.py's _score_layer2a."""
    logger = logging.getLogger("vlaw")
    try:
        conn = await aiosqlite.connect(DB_PATH)
        conn.row_factory = aiosqlite.Row
        try:
            cur = await conn.execute("SELECT row_hash FROM event_chain ORDER BY id DESC LIMIT 1")
            last = await cur.fetchone()
            prev_hash = last["row_hash"] if last else GENESIS_HASH

            cur = await conn.execute("SELECT MAX(event_id) m FROM event_chain")
            last_sealed_id = (await cur.fetchone())["m"] or 0

            cur = await conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (last_sealed_id, SEAL_BATCH_LIMIT),
            )
            rows = await cur.fetchall()
            sealed = 0
            for row in rows:
                row_dict = dict(row)
                row_hash = compute_row_hash(row_dict, prev_hash)
                await conn.execute(
                    "INSERT INTO event_chain (event_id, row_hash, prev_hash) VALUES (?, ?, ?)",
                    (row_dict["id"], row_hash, prev_hash),
                )
                prev_hash = row_hash
                sealed += 1
            if sealed:
                await conn.commit()
            return sealed
        finally:
            await conn.close()
    except Exception:
        logger.exception("evidence chain sealing failed")
        return 0


async def get_chain_head(db) -> dict:
    """Current chain state: how many events are sealed, the latest
    row_hash, and whether any events exist that haven't been sealed yet
    (a nonzero `unsealed_count` is informational, not an error -- it just
    means the next scheduled seal hasn't run yet)."""
    cur = await db.execute("SELECT COUNT(*) c, MAX(event_id) m FROM event_chain")
    row = await cur.fetchone()
    sealed_count, last_sealed_id = row["c"], row["m"] or 0

    cur = await db.execute("SELECT row_hash FROM event_chain ORDER BY id DESC LIMIT 1")
    last = await cur.fetchone()
    head_hash = last["row_hash"] if last else GENESIS_HASH

    cur = await db.execute("SELECT COUNT(*) c FROM events WHERE id > ?", (last_sealed_id,))
    unsealed_count = (await cur.fetchone())["c"]

    return {
        "sealed_count": sealed_count,
        "head_hash": head_hash,
        "last_sealed_event_id": last_sealed_id,
        "unsealed_count": unsealed_count,
    }


async def verify_chain(db) -> dict:
    """Re-walks every sealed event in order, recomputing each hash from
    the event row's CURRENT content and comparing it to what was stored
    when it was sealed. A mismatch means that event row was edited after
    sealing. Also checks: (a) every event_id in event_chain still exists
    in events (catches deletion), (b) event_chain's own prev_hash values
    form an unbroken chain (catches a chain row being deleted or
    reordered). Returns as soon as the first problem is found, plus a
    summary. valid=True with checked_count=0 is the correct result on a
    fresh install with nothing sealed yet -- not an error."""
    cur = await db.execute("SELECT * FROM event_chain ORDER BY id ASC")
    chain_rows = await cur.fetchall()

    expected_prev = GENESIS_HASH
    checked = 0
    for chain_row in chain_rows:
        chain_row = dict(chain_row)
        if chain_row["prev_hash"] != expected_prev:
            return {
                "valid": False, "checked_count": checked,
                "reason": "broken_link",
                "detail": f"event_chain row id={chain_row['id']} (event_id={chain_row['event_id']}) "
                          f"has prev_hash that doesn't match the previous row's row_hash",
            }

        cur2 = await db.execute("SELECT * FROM events WHERE id = ?", (chain_row["event_id"],))
        event_row = await cur2.fetchone()
        if event_row is None:
            return {
                "valid": False, "checked_count": checked,
                "reason": "event_deleted",
                "detail": f"event_id={chain_row['event_id']} was sealed but no longer exists in events",
            }

        recomputed = compute_row_hash(dict(event_row), chain_row["prev_hash"])
        if recomputed != chain_row["row_hash"]:
            return {
                "valid": False, "checked_count": checked,
                "reason": "hash_mismatch",
                "detail": f"event_id={chain_row['event_id']} was modified after being sealed",
            }

        expected_prev = chain_row["row_hash"]
        checked += 1

    return {"valid": True, "checked_count": checked, "reason": None, "detail": None}
