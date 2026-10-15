"""The signed evidence bundle (Stage 3 of docs/design/evidence-anchoring.md, section 5.3).

One zip holding what a third party needs to re-check a range of events offline with
verifier/vigil_verify.py, without Vigil and without trusting this machine's database:

  events.jsonl      the events of the range with their chain rows (see docs/design/evidence-bundle-spec.md)
  chain-proof.json  the manifest: install id, public key and fingerprint, the period, the SHA-256 of every
                    other file, the chain start, the anchors that bind the range with any stored timestamp
                    tokens, and the limits
  chain-proof.sig   Ed25519 signature over the exact bytes of chain-proof.json (core/signing_key.py)
  coverage.json     the "What this report covers" block
  gaps.json         the monitoring gaps that overlap the range

Nothing else is in it: no settings, no private key, no webhook address, no timestamp-service address
other than the one already recorded in a token's anchor entry. The signature proves the bundle was not
edited after export by anyone without the key. The same Windows user can read the key, so it does not
prove who exported it, and it proves nothing about whether the events are true or complete.
"""

import base64
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from core import evidence_anchor, report_coverage, signing_key
from core.evidence_chain import GENESIS_HASH, seal_new_events

BUNDLE_SPEC = "vigil-evidence-bundle-1"
VERIFIER_SPEC_VERSION = 1
MAX_ROWS = 200_000

# The 14 hashed columns of events, in the order core/evidence_chain.py hashes them.
EVENT_COLUMNS = (
    "id", "agent_id", "session_id", "event_type", "path", "detail", "file_count", "data_volume_bytes",
    "severity", "anomaly_score", "pid", "behaviour_score", "event_source", "created_at",
)

LIMITS = [
    "The signature proves the bundle was not edited after export by anyone without the signing key. The key is "
    "readable by the Windows user that runs Vigil, so it does not show who exported the bundle.",
    "A timestamp token, if present, covers only what existed when its anchor was made. Events after the newest "
    "token are anchored locally only.",
    "Completeness is not established: events that were never recorded (file reads, network, MCP, short-lived "
    "processes) are not in the bundle, and nothing here can show they happened.",
    "Alerts, sessions, audit entries and monitoring-gap records are not integrity-protected in this version; "
    "only the event chain is.",
]


class BundleError(Exception):
    """The range cannot be exported (nothing sealed in it, too large, or bad dates)."""


def _text(value):
    """The canonical text of one column, exactly what the chain hashes (str(), None stays None)."""
    return None if value is None else str(value)


def _parse_day(value: str, label: str) -> str:
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        raise BundleError(f"{label} must be a date as YYYY-MM-DD") from None


async def build_bundle(start: str, end: str, *, db_path=None, key_directory: Path | None = None,
                       now: datetime | None = None) -> tuple[bytes, dict]:
    """Returns (zip bytes, summary). start and end are UTC calendar dates, inclusive, compared with the date
    part of events.created_at. Seals pending events and records an export anchor first, so the range is bound
    by an anchor that exists now."""
    start, end = _parse_day(start, "start"), _parse_day(end, "end")
    if end < start:
        raise BundleError("end is before start")
    directory = key_directory or evidence_anchor.key_dir()

    while await seal_new_events():
        pass
    await evidence_anchor.create_anchor("export", db_path=db_path, key_directory=directory, now=now)

    conn = await evidence_anchor.connect(db_path)
    try:
        cur = await conn.execute(
            "SELECT MIN(e.id) lo, MAX(e.id) hi FROM events e JOIN event_chain c ON c.event_id = e.id "
            "WHERE substr(e.created_at, 1, 10) BETWEEN ? AND ?", (start, end))
        bounds = await cur.fetchone()
        if bounds["lo"] is None:
            raise BundleError("There are no sealed events in that date range.")
        first_id, range_last_id = bounds["lo"], bounds["hi"]

        # The first anchor at or after the last event of the range binds its end; the rows run through that
        # anchor's last event so the verifier can recompute the head the anchor recorded.
        cur = await conn.execute("SELECT * FROM evidence_anchors WHERE last_event_id >= ? ORDER BY anchor_seq LIMIT 1", (range_last_id,))
        end_anchor = await cur.fetchone()
        last_id = max(range_last_id, end_anchor["last_event_id"]) if end_anchor else range_last_id
        # The last anchor before the range starts the anchor chain.
        cur = await conn.execute("SELECT * FROM evidence_anchors WHERE last_event_id < ? ORDER BY anchor_seq DESC LIMIT 1", (first_id,))
        start_anchor = await cur.fetchone()

        cur = await conn.execute(
            "SELECT c.id chain_id, c.event_id, c.row_hash, c.prev_hash, e.* FROM event_chain c "
            "LEFT JOIN events e ON e.id = c.event_id WHERE c.event_id BETWEEN ? AND ? ORDER BY c.id", (first_id, last_id))
        rows = await cur.fetchall()
        if len(rows) > MAX_ROWS:
            raise BundleError(f"That range holds {len(rows)} events; the limit for one bundle is {MAX_ROWS}. Choose a shorter range.")

        lines = []
        for r in rows:
            event = None if r["id"] is None else {col: _text(r[col]) for col in EVENT_COLUMNS}
            lines.append(json.dumps({"event_id": r["event_id"], "event": event, "row_hash": r["row_hash"], "prev_hash": r["prev_hash"]},
                                    sort_keys=True, separators=(",", ":")))
        events_bytes = ("\n".join(lines) + "\n").encode("utf-8")

        anchor_rows = []
        if end_anchor is not None:
            low = start_anchor["anchor_seq"] if start_anchor else 1
            cur = await conn.execute("SELECT * FROM evidence_anchors WHERE anchor_seq BETWEEN ? AND ? ORDER BY anchor_seq",
                                     (low, end_anchor["anchor_seq"]))
            anchor_rows = await cur.fetchall()

        anchors = []
        for a in anchor_rows:
            token = a["tsa_token"]
            anchors.append({
                "anchor_seq": a["anchor_seq"], "anchor_json": a["anchor_json"], "anchor_hash": a["anchor_hash"],
                "status": a["status"], "tsa_name": a["tsa_name"], "timestamped_at": a["timestamped_at"],
                "tsa_token_b64": base64.b64encode(bytes(token)).decode() if token else None,
            })

        range_start_text, range_end_text = f"{start} 00:00:00", f"{end} 23:59:59"
        cur = await conn.execute(
            "SELECT run_id, gap_start, gap_end, reason FROM monitoring_gaps WHERE gap_end >= ? AND gap_start <= ? ORDER BY gap_start",
            (range_start_text, range_end_text))
        gaps = [dict(g) for g in await cur.fetchall()]
    finally:
        await conn.close()

    install_id = (evidence_anchor.load_state(directory) or {}).get("install_id") or (
        json.loads(anchors[-1]["anchor_json"]).get("install_id") if anchors else None)
    key = signing_key.ensure_key(directory, install_id)

    coverage_bytes = json.dumps(report_coverage.as_dict(), indent=2, sort_keys=True).encode("utf-8")
    gaps_bytes = json.dumps(gaps, indent=2, sort_keys=True).encode("utf-8")
    files = {"events.jsonl": events_bytes, "coverage.json": coverage_bytes, "gaps.json": gaps_bytes}
    proof = {
        "v": 1,
        "spec": BUNDLE_SPEC,
        "verifier_spec_version": VERIFIER_SPEC_VERSION,
        "install_id": key["install_id"] if key.get("install_id") else install_id,
        "public_key": key["public_key"],
        "public_key_fingerprint": key["fingerprint"],
        "created_at": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "period": {"start": start, "end": end, "basis": "UTC date of events.created_at, inclusive"},
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        "chain": {
            "genesis": GENESIS_HASH,
            "prev_hash": rows[0]["prev_hash"],
            "first_event_id": first_id,
            "range_last_event_id": range_last_id,
            "last_event_id": last_id,
            "row_count": len(rows),
        },
        "anchors": anchors,
        "limits": LIMITS,
    }
    proof_bytes = json.dumps(proof, indent=2, sort_keys=True).encode("utf-8")
    signature = base64.b64encode(signing_key.sign(directory, proof_bytes))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("chain-proof.json", proof_bytes)
        bundle.writestr("chain-proof.sig", signature)
        for name, data in files.items():
            bundle.writestr(name, data)

    summary = {
        "install_id": proof["install_id"], "fingerprint": key["fingerprint"], "period": proof["period"],
        "events": len(rows), "anchors": len(anchors), "tokens": sum(1 for a in anchors if a["tsa_token_b64"]),
        "bound_by_anchor": end_anchor["anchor_seq"] if end_anchor else None,
    }
    return buffer.getvalue(), summary
