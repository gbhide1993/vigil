"""Local evidence anchors: Stage 1 of docs/design/evidence-anchoring.md.

An anchor pins, at one moment, the head of the event hash chain (core/evidence_chain.py), the
sealed count, the last sealed event id and a digest of the tables the chain does not cover. Anchors
form their own chain (each carries the hash of the previous one), and the sequence counter, the
install id and the last anchor hash are also kept in a small file in the key directory, outside the
database, so deleting vlaw.db does not reset them.

What this gives, and what it does not (see "Stage 1 limits" in the design doc): an anchor makes an
edit, a truncation or a deleted database visible to Vigil's own check against the anchors, but anyone
who can write the database AND the key directory can rewrite both. Nothing here leaves the machine
and nothing here is an external timestamp; that is Stage 2.

Creating an anchor never re-hashes the chain: it reads the head row and the row count. The digest of
the other tables is linear in their size (measured in the design notes).
"""

import asyncio
import hashlib
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from core import evidence_chain
from core.evidence_chain import GENESIS_HASH

logger = logging.getLogger("vlaw")

ANCHOR_VERSION = 1
STATE_FILE_NAME = "anchor-state.json"

# The scheduled job runs hourly; this guard keeps two anchors from landing close together if the job
# and an export or a restart coincide.
MIN_HOURLY_INTERVAL_SECONDS = 55 * 60

# Tables whose rows the chain does not cover. Digest order is fixed: this tuple, then rowid within each
# table (for the integer-keyed tables rowid is the primary key; for sessions and policy it is insertion
# order), columns in the order SELECT * returns them.
DIGEST_TABLES = ("alerts", "audit_log", "sessions", "monitoring_gaps", "vigil_runs", "policy")

TRIGGERS = ("hourly", "export", "startup_gap")

_anchor_lock = asyncio.Lock()


def _crash_point(name: str) -> None:
    """A seam for tests: they replace this to raise at a named point and simulate a crash there.
    Points: "state_pending_written" (key directory written, row not yet inserted) and
    "anchor_committed" (row committed, key directory not yet advanced)."""


# ------------------------------------------------------------------ key directory state

def key_dir() -> Path:
    """The directory kept outside the data directory. main.py sets VLAW_KEY_DIR to
    %LOCALAPPDATA%\\V-LAW\\keys; without it (tests, dev) it falls back to a folder inside the data directory."""
    configured = os.environ.get("VLAW_KEY_DIR")
    if configured:
        return Path(configured)
    return Path(os.environ.get("VLAW_DATA_DIR", "./data")) / "keys"


def load_state(directory: Path | None = None) -> dict | None:
    path = (directory or key_dir()) / STATE_FILE_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("install_id") else None


def save_state(state: dict, directory: Path | None = None) -> None:
    directory = directory or key_dir()
    directory.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".anchor-state-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp, directory / STATE_FILE_NAME)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ------------------------------------------------------------------ canonical form and digest

def canonical_json(anchor: dict) -> str:
    return json.dumps(anchor, sort_keys=True, separators=(",", ":"))


def anchor_hash_of(anchor_json: str) -> str:
    return hashlib.sha256(anchor_json.encode("utf-8")).hexdigest()


def _now_text(now: datetime | None = None) -> str:
    return (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


async def tables_digest(conn: aiosqlite.Connection) -> str:
    """SHA-256 over the rows of DIGEST_TABLES. Linear in the size of those tables."""
    digest = hashlib.sha256()
    for table in DIGEST_TABLES:
        cur = await conn.execute(f"SELECT * FROM {table} ORDER BY rowid")
        names = [d[0] for d in cur.description]
        digest.update(json.dumps([table, names], separators=(",", ":")).encode("utf-8"))
        while True:
            rows = await cur.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                digest.update(json.dumps(list(tuple(row)), separators=(",", ":"), default=str).encode("utf-8"))
                digest.update(b"\n")
        digest.update(b"\x00")
    return digest.hexdigest()


async def _chain_position(conn: aiosqlite.Connection) -> dict:
    """The chain head, the sealed count and the last sealed event id. Reads the head row and counts
    rows; it never recomputes a hash."""
    cur = await conn.execute("SELECT event_id, row_hash FROM event_chain ORDER BY id DESC LIMIT 1")
    last = await cur.fetchone()
    cur = await conn.execute("SELECT COUNT(*) c FROM event_chain")
    count = (await cur.fetchone())["c"]
    return {
        "chain_head": last["row_hash"] if last else GENESIS_HASH,
        "event_count": count,
        "last_event_id": last["event_id"] if last else 0,
    }


async def _last_anchor(conn: aiosqlite.Connection):
    cur = await conn.execute("SELECT * FROM evidence_anchors ORDER BY anchor_seq DESC LIMIT 1")
    return await cur.fetchone()


async def connect(db_path=None) -> aiosqlite.Connection:
    """A read connection to the evidence database (evidence_chain.DB_PATH unless a path is given)."""
    conn = await aiosqlite.connect(db_path or evidence_chain.DB_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA busy_timeout = 5000")
    return conn


# ------------------------------------------------------------------ creating anchors

async def create_anchor(trigger: str, *, db_path=None, key_directory: Path | None = None,
                        now: datetime | None = None) -> dict | None:
    """Records an anchor and returns it (a dict of the stored row), or None when none is due or it failed.

    hourly       only if the chain head or count changed since the last anchor, and at least
                 MIN_HOURLY_INTERVAL_SECONDS after it.
    export       always bound to a state that exists now: a new anchor, unless the last anchor already
                 pins exactly this head and these table rows, in which case that anchor is returned
                 (with "reused": True) so repeated report previews do not pile up anchors.
    startup_gap  always (a restart after a gap is itself pinned).

    Never raises: a failure is logged and returns None."""
    if trigger not in TRIGGERS:
        raise ValueError(f"unknown anchor trigger {trigger!r}")
    try:
        async with _anchor_lock:
            conn = await connect(db_path)
            try:
                return await _create_locked(conn, trigger, key_directory, now)
            finally:
                await conn.close()
    except Exception:
        logger.exception("evidence anchor: could not record an anchor (%s)", trigger)
        return None


async def _create_locked(conn, trigger: str, key_directory, now) -> dict | None:
    position = await _chain_position(conn)
    last = await _last_anchor(conn)
    created_at = _now_text(now)

    if trigger == "hourly":
        if last is None:
            if position["event_count"] == 0:
                return None
        else:
            unchanged = last["chain_head"] == position["chain_head"] and last["event_count"] == position["event_count"]
            age = (_parse_time(created_at) - _parse_time(last["created_at"])).total_seconds()
            if unchanged or age < MIN_HOURLY_INTERVAL_SECONDS:
                return None

    digest = await tables_digest(conn)
    if (trigger == "export" and last is not None and last["chain_head"] == position["chain_head"]
            and last["event_count"] == position["event_count"] and last["tables_digest"] == digest):
        return {**dict(last), "reused": True}

    state = load_state(key_directory)
    install_id = (state or {}).get("install_id") or (last["install_id"] if last else None) or str(uuid.uuid4())

    state_seq = int((state or {}).get("anchor_seq", 0))
    db_seq = last["anchor_seq"] if last else 0
    if state_seq > db_seq:
        # The database lost anchors the key directory remembers: continue the series from the
        # remembered position so the break stays visible to the check.
        anchor_seq, prev_hash = state_seq + 1, (state or {}).get("last_anchor_hash", GENESIS_HASH)
    elif last is not None:
        anchor_seq, prev_hash = last["anchor_seq"] + 1, last["anchor_hash"]
    else:
        anchor_seq, prev_hash = 1, GENESIS_HASH

    anchor = {
        "v": ANCHOR_VERSION,
        "install_id": install_id,
        "anchor_seq": anchor_seq,
        "prev_anchor_hash": prev_hash,
        "chain_head": position["chain_head"],
        "event_count": position["event_count"],
        "last_event_id": position["last_event_id"],
        "meta_head": None,
        "tables_digest": digest,
        "created_at": created_at,
    }
    anchor_json = canonical_json(anchor)
    anchor_hash = anchor_hash_of(anchor_json)

    # Two steps, so a crash between the database commit and the key directory write is not mistaken for
    # tampering. First the key directory records the anchor it is about to add as PENDING (its committed
    # fields still describe the last anchor). Then the row is committed. Then the committed fields move
    # forward and the pending marker is cleared. A crash after the first step leaves a pending anchor the
    # database never got (ignored; the next anchor reuses the number, since no row has it). A crash after
    # the second step leaves the database one anchor ahead of the key directory (which the check accepts).
    committed = {
        "v": 1, "install_id": install_id,
        "anchor_seq": state_seq,
        "last_anchor_hash": (state or {}).get("last_anchor_hash", GENESIS_HASH),
        "last_chain_head": (state or {}).get("last_chain_head", GENESIS_HASH),
        "last_event_count": (state or {}).get("last_event_count", 0),
    }
    save_state({**committed, "pending_seq": anchor_seq, "pending_hash": anchor_hash, "updated_at": created_at}, key_directory)
    _crash_point("state_pending_written")
    await conn.execute(
        "INSERT INTO evidence_anchors (anchor_seq, anchor_json, anchor_hash, prev_anchor_hash, chain_head, event_count, "
        "last_event_id, tables_digest, install_id, created_at, trigger, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'local_only')",
        (anchor_seq, anchor_json, anchor_hash, prev_hash, position["chain_head"], position["event_count"],
         position["last_event_id"], digest, install_id, created_at, trigger),
    )
    await conn.commit()
    _crash_point("anchor_committed")
    save_state({
        "v": 1, "install_id": install_id, "anchor_seq": anchor_seq, "last_anchor_hash": anchor_hash,
        "last_chain_head": position["chain_head"], "last_event_count": position["event_count"], "updated_at": created_at,
    }, key_directory)
    return {**anchor, "anchor_hash": anchor_hash, "trigger": trigger, "status": "local_only", "reused": False}


# ------------------------------------------------------------------ checking anchors

def _public(anchor_row) -> dict:
    return {
        "anchor_seq": anchor_row["anchor_seq"], "created_at": anchor_row["created_at"],
        "chain_head": anchor_row["chain_head"], "event_count": anchor_row["event_count"],
        "last_event_id": anchor_row["last_event_id"], "status": anchor_row["status"], "trigger": anchor_row["trigger"],
    }


async def check_anchors(*, db_path=None, key_directory: Path | None = None) -> dict:
    """Checks every stored anchor against the chain as it is now, and the anchor series against the key
    directory. Result keys:

      anchors_checked, anchors_mismatched, first_mismatch ({anchor_seq, kind, detail} or None)
      last_anchor            the newest stored anchor (public fields) or None
      anchoring              "none" (no anchor at all) or "local_only"
      status                 "none", "ok", "shorter_than_local_anchor", "disagrees_with_local_anchor" or
                             "anchor_continuity_break"
      continuity             {"status": "none" | "ok" | "break", "kind": ..., "detail": ...}

    Mismatch kinds: shorter (the chain has fewer sealed events than the anchor recorded, which is what a
    truncation looks like), disagrees (the chain has a different hash at the anchored event) and altered
    (the stored anchor no longer matches its own hash). Continuity kinds: series_restarted (the key
    directory remembers anchors the database does not hold), history_missing, link_broken, install_changed,
    state_missing."""
    conn = await connect(db_path)
    try:
        # One pass: each anchor joined to the chain row of its last event (an indexed lookup), not one query per anchor.
        cur = await conn.execute(
            "SELECT a.anchor_seq, a.anchor_json, a.anchor_hash, a.prev_anchor_hash, a.chain_head, a.event_count, "
            "a.last_event_id, a.install_id, a.created_at, a.trigger, a.status, a.attempts, a.error, "
            "c.row_hash AS chain_row_hash FROM evidence_anchors a "
            "LEFT JOIN event_chain c ON c.event_id = a.last_event_id ORDER BY a.anchor_seq ASC"
        )
        anchors = await cur.fetchall()
        cur = await conn.execute("SELECT COUNT(*) c, MAX(event_id) m FROM event_chain")
        row = await cur.fetchone()
        chain_count, chain_max_event = row["c"], row["m"] or 0

        mismatches: list[dict] = []
        for anchor in anchors:
            problem = None
            expected_json = anchor["anchor_json"]
            try:
                fields = json.loads(expected_json)
            except ValueError:
                fields = {}
            if (anchor_hash_of(expected_json) != anchor["anchor_hash"] or fields.get("chain_head") != anchor["chain_head"]
                    or fields.get("event_count") != anchor["event_count"] or fields.get("anchor_seq") != anchor["anchor_seq"]
                    or fields.get("last_event_id") != anchor["last_event_id"] or fields.get("prev_anchor_hash") != anchor["prev_anchor_hash"]):
                problem = ("altered", f"anchor {anchor['anchor_seq']} no longer matches its own hash")
            elif chain_count < anchor["event_count"] or chain_max_event < anchor["last_event_id"]:
                problem = ("shorter", f"anchor {anchor['anchor_seq']} recorded {anchor['event_count']} sealed events "
                                      f"(last event {anchor['last_event_id']}), the chain has {chain_count} (last event {chain_max_event})")
            elif anchor["event_count"] > 0:
                if anchor["chain_row_hash"] != anchor["chain_head"]:
                    problem = ("disagrees", f"the chain has a different hash at event {anchor['last_event_id']} than anchor {anchor['anchor_seq']} recorded")
            elif anchor["chain_head"] != GENESIS_HASH:
                problem = ("altered", f"anchor {anchor['anchor_seq']} records an empty chain with a non-empty head")
            if problem:
                mismatches.append({"anchor_seq": anchor["anchor_seq"], "kind": problem[0], "detail": problem[1]})

        timestamps, timestamp_problems = await _review_timestamps(conn, anchors)
        mismatches.extend(timestamp_problems)

        continuity = _check_continuity(anchors, load_state(key_directory))
        last_public = _public(anchors[-1]) if anchors else None

        # The most serious kind first: truncation, then a different hash, then an altered anchor row.
        order = {"shorter": 0, "disagrees": 1, "altered": 2, "timestamp": 3}
        first = min(mismatches, key=lambda m: (order[m["kind"]], m["anchor_seq"])) if mismatches else None
        if first and first["kind"] == "shorter":
            status = "shorter_than_local_anchor"
        elif first and first["kind"] == "timestamp":
            status = "timestamp_mismatch"
        elif first:
            status = "disagrees_with_local_anchor"
        elif continuity["status"] == "break":
            status = "anchor_continuity_break"
        elif anchors:
            status = "ok"
        else:
            status = "none"
        return {
            "anchors_checked": len(anchors),
            "anchors_mismatched": len(mismatches),
            "first_mismatch": first,
            "last_anchor": last_public,
            "anchoring": (timestamps["status"] if timestamps["timestamped"] else "local_only") if anchors else "none",
            "timestamps": timestamps,
            "status": status,
            "continuity": continuity,
        }
    finally:
        await conn.close()


async def _review_timestamps(conn, anchors) -> tuple[dict, list[dict]]:
    """Stage 2: what the stored external timestamp tokens say, read from the database; nothing is fetched.

    Every held token is parsed and its message imprint must equal its anchor's hash; a token that does not
    match is a mismatch (kind "timestamp") and the anchor does not count as timestamped. The signature is
    checked only for the newest timestamped anchor, and only against a certificate the user supplied
    (external_timestamp_ca_pem); with none, that token is reported as timestamp_unverified_signature.
    Overall status: "none" (no anchors), "local_only" (no valid token), "partially_timestamped" (some, but
    the newest anchor has none: events after the newest token are anchored locally only) or
    "externally_timestamped" (the newest anchor has a valid token). Anchors recorded before timestamping
    was turned on are not back-filled; the newest token covers them through the anchor hash chain."""
    from core import external_timestamp as ts

    settings = await ts.load_settings(conn)
    cur = await conn.execute(
        "SELECT anchor_seq, tsa_token, tsa_name, timestamped_at FROM evidence_anchors WHERE status = 'timestamped' ORDER BY anchor_seq")
    held = {r["anchor_seq"]: r for r in await cur.fetchall()}
    problems: list[dict] = []
    valid: dict[int, dict] = {}
    by_seq = {a["anchor_seq"]: a for a in anchors}
    for seq, row in held.items():
        anchor = by_seq.get(seq)
        if anchor is None or row["tsa_token"] is None:
            continue
        try:
            gen_time = ts.check_imprint(bytes(row["tsa_token"]), anchor["anchor_hash"])
        except ts.TimestampError as exc:
            problems.append({"anchor_seq": seq, "kind": "timestamp",
                             "detail": f"the timestamp token held for anchor {seq} does not match the anchor ({exc})"})
            continue
        valid[seq] = {"tsa": row["tsa_name"], "tsa_time": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ")}

    latest = None
    if valid:
        seq = max(valid)
        signature = ts.check_signature(bytes(held[seq]["tsa_token"]), settings["ca_pem"])
        if signature["signature"] == ts.SIGNATURE_FAILED:
            problems.append({"anchor_seq": seq, "kind": "timestamp",
                             "detail": f"the timestamp signature on anchor {seq} failed: {signature['detail']}"})
            valid.pop(seq)
            seq = max(valid) if valid else None
            signature = ts.check_signature(bytes(held[seq]["tsa_token"]), settings["ca_pem"]) if seq else None
        if seq is not None and signature is not None:
            latest = {"anchor_seq": seq, "anchor_time": by_seq[seq]["created_at"], "tsa": valid[seq]["tsa"],
                      "tsa_time": valid[seq]["tsa_time"], "signature": signature["signature"],
                      "signature_detail": signature["detail"]}

    since = settings["since_seq"] or 1
    eligible = [a for a in anchors if a["anchor_seq"] >= since]
    if not anchors:
        overall = "none"
    elif not valid:
        overall = "local_only"
    elif anchors[-1]["anchor_seq"] in valid:
        overall = "externally_timestamped"
    else:
        overall = "partially_timestamped"
    recent = [
        {"anchor_seq": a["anchor_seq"], "status": "externally_timestamped" if a["anchor_seq"] in valid else "local_only",
         "queue_status": a["status"], "attempts": a["attempts"]}
        for a in anchors[-20:]
    ]
    return {
        "status": overall, "timestamped": len(valid), "eligible": len(eligible),
        "enabled": ts.is_active(settings),
        # Anchors that should have a token and do not (no network, no reply yet). Zero while the feature is off.
        "waiting": sum(1 for a in eligible if a["anchor_seq"] not in valid) if ts.is_active(settings) else 0,
        "latest": latest, "recent": recent,
    }, problems


def _check_continuity(anchors, state: dict | None) -> dict:
    if not anchors:
        if state and int(state.get("anchor_seq", 0)) > 0:
            return {"status": "break", "kind": "series_restarted",
                    "detail": f"the key directory records anchors up to seq {state['anchor_seq']}, this database holds none "
                              "(the database was replaced or its anchors were removed)"}
        return {"status": "none", "kind": None, "detail": None}

    if anchors[0]["anchor_seq"] != 1:
        return {"status": "break", "kind": "history_missing",
                "detail": f"this database holds anchors from seq {anchors[0]['anchor_seq']}; anchors 1 to {anchors[0]['anchor_seq'] - 1} "
                          "are not in it (the database was replaced or its anchors were removed)"}
    previous = None
    for anchor in anchors:
        if previous is None:
            linked = anchor["prev_anchor_hash"] == GENESIS_HASH
        else:
            linked = anchor["anchor_seq"] == previous["anchor_seq"] + 1 and anchor["prev_anchor_hash"] == previous["anchor_hash"]
        if not linked:
            before = previous["anchor_seq"] if previous else 0
            return {"status": "break", "kind": "link_broken",
                    "detail": f"BREAK between seq {before} and seq {anchor['anchor_seq']}"}
        if previous is not None and (anchor["event_count"] < previous["event_count"] or anchor["last_event_id"] < previous["last_event_id"]):
            return {"status": "break", "kind": "link_broken",
                    "detail": f"BREAK between seq {previous['anchor_seq']} and seq {anchor['anchor_seq']}: the recorded chain position went backwards"}
        if previous is not None and anchor["install_id"] != previous["install_id"]:
            return {"status": "break", "kind": "install_changed",
                    "detail": f"the install id changes between seq {previous['anchor_seq']} and seq {anchor['anchor_seq']}"}
        previous = anchor

    newest = anchors[-1]
    if state is None:
        return {"status": "break", "kind": "state_missing",
                "detail": "the key directory record is missing, so the anchor series cannot be checked against it"}
    if state.get("install_id") != newest["install_id"]:
        return {"status": "break", "kind": "install_changed",
                "detail": "the key directory's install id differs from the one in the anchors"}
    state_seq = int(state.get("anchor_seq", 0))
    if state_seq > newest["anchor_seq"]:
        return {"status": "break", "kind": "series_restarted",
                "detail": f"the key directory records anchors up to seq {state_seq}, this database holds up to seq {newest['anchor_seq']} "
                          "(the database was replaced or its newest anchors were removed)"}
    if state_seq == newest["anchor_seq"] and state.get("last_anchor_hash") != newest["anchor_hash"]:
        return {"status": "break", "kind": "link_broken",
                "detail": f"anchor {state_seq} differs from the hash the key directory recorded for it"}
    return {"status": "ok", "kind": None, "detail": None}
