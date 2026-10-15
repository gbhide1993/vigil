# Vigil evidence bundle: format and verification rules

Spec id `vigil-evidence-bundle-1`, verifier spec version 1. This page is written so that a third party can
reimplement the check without reading Vigil's code. The reference implementation is `verifier/vigil_verify.py`
(Python standard library and `cryptography`, no network). Background and limits: `evidence-anchoring.md`, sections 5, 6 and 14.

A bundle is a zip with exactly these members. Nothing else belongs in it.

| Member | What it is |
|---|---|
| `chain-proof.json` | The manifest (UTF-8 JSON). Signed. |
| `chain-proof.sig` | Base64 of a 64-byte Ed25519 signature over the exact bytes of `chain-proof.json`. |
| `events.jsonl` | One JSON object per line: the events of the range with their chain rows. |
| `coverage.json` | The "What this report covers" block that Vigil prints in its reports: `{"title", "lines"}`. |
| `gaps.json` | The monitoring gaps that overlap the period: `[{"run_id", "gap_start", "gap_end", "reason"}]`. |

## 1. The manifest (`chain-proof.json`)

```
{
  "v": 1, "spec": "vigil-evidence-bundle-1", "verifier_spec_version": 1,
  "install_id": "<uuid>",
  "public_key": "<base64, 32 raw bytes, Ed25519>",
  "public_key_fingerprint": "<hex SHA-256 of those 32 bytes>",
  "created_at": "2026-10-01T13:00:00Z",
  "period": {"start": "2026-10-01", "end": "2026-10-01", "basis": "UTC date of events.created_at, inclusive"},
  "files": {"events.jsonl": "<hex SHA-256>", "coverage.json": "<hex>", "gaps.json": "<hex>"},
  "chain": {"genesis": "000...0", "prev_hash": "<hash before the first row>", "first_event_id": 10,
            "range_last_event_id": 40, "last_event_id": 44, "row_count": 35},
  "anchors": [ {"anchor_seq": 3, "anchor_json": "<string>", "anchor_hash": "<hex>", "status": "...",
                "tsa_name": "<url or null>", "timestamped_at": "<genTime or null>", "tsa_token_b64": "<base64 DER or null>"} ],
  "limits": ["..."]
}
```

`last_event_id` is the id of the last exported row; it is at least `range_last_event_id` because the rows run
through the last event of the first anchor that binds the end of the range.

## 2. The chain: canonical form (the part a reimplementation must get exactly right)

Each exported event has 14 fields, in this fixed order:

`id, agent_id, session_id, event_type, path, detail, file_count, data_volume_bytes, severity, anomaly_score, pid, behaviour_score, event_source, created_at`

In `events.jsonl` every field is already written as the text the hash uses (a string), or `null`. The canonical string of an event is:

- each field as that text, where `None` becomes the empty string (a `null` and an empty string hash the same);
- the 14 values joined with `|`.

The row hash is

`row_hash = lowercase hex SHA-256 of the UTF-8 bytes of ( prev_hash + canonical_string )`

where `prev_hash` is the previous row's `row_hash` as a 64-character lowercase hex string, and for the very
first event Vigil ever sealed it is the genesis value, 64 zeros
(`0000000000000000000000000000000000000000000000000000000000000000`). There is no key: anyone can compute it, which is why anchors exist.

Worked example. For the event `1|2|s|file_write|/p||1|0|low|0.5|||poll|2026-10-01 07:00:00` and the genesis
`prev_hash`, `row_hash` is `9a2bfa0503512943b80e158bc50b8660eeeaeac59de57675c4345ae4dcde1aec`.

A line of `events.jsonl`:

```
{"event": {"id": "1", "agent_id": "2", ... "created_at": "2026-10-01 07:00:00"}, "event_id": 1, "prev_hash": "<hex>", "row_hash": "<hex>"}
```

`event` is `null` if the chain row exists but the event it names no longer does (an export of a damaged database).

Checks on the rows, in order, each a failure if violated: `event` present; `event.id` equals `event_id`; ids strictly
increase; the first row's `prev_hash` equals the manifest's `chain.prev_hash` and every later `prev_hash` equals the previous `row_hash`;
the recomputed hash equals `row_hash`; the number of rows equals `chain.row_count`; the first and last ids equal `chain.first_event_id` and `chain.last_event_id`.

## 3. Anchors

An anchor is a JSON object serialised canonically (keys sorted, separators `,` and `:`, no spaces; this is the `anchor_json` string).
`anchor_hash` is the hex SHA-256 of the UTF-8 bytes of `anchor_json`. Fields:

`v` (1 or 2), `install_id`, `anchor_seq`, `prev_anchor_hash`, `chain_head`, `event_count`, `last_event_id`, `meta_head` (null), `tables_digest`, `created_at`,
and, in format 2 only, `key_fingerprint` (the fingerprint of the install's signing key). The first anchor ever made has `prev_anchor_hash` equal to the genesis value.

Checks: `anchor_hash` equals the hash of `anchor_json`; `anchor_seq` inside the JSON equals the entry's; `install_id` equals the manifest's;
consecutive entries have consecutive `anchor_seq`, `prev_anchor_hash` equal to the previous `anchor_hash`, and a non-decreasing `event_count`.

Binding: for an anchor whose `last_event_id` lies inside the exported rows, `chain_head` must equal the `row_hash` of the exported row with that event id.
At least one anchor must have `last_event_id` at or beyond `range_last_event_id` for the end of the range to be bound; if none does the check is **NOT CHECKED**, not passed.
`tables_digest` is not checked (the tables it covers change legitimately; see `evidence-anchoring.md`).

Key: the fingerprint of `public_key` must equal `public_key_fingerprint`; every format 2 anchor's `key_fingerprint` must equal it. With no format 2 anchor the check is **NOT CHECKED**.

## 4. Signature

`chain-proof.sig` verifies, with the Ed25519 public key in the manifest, over the exact bytes of `chain-proof.json` as stored.
Every file named in `files` must exist with the listed SHA-256, and no member other than the five above may exist.

The key is created on the machine that exports and can be read by the Windows user that runs Vigil. A valid signature shows the manifest and the files it lists
were not changed after they were signed by anyone who did not hold the key. It does not show who exported the bundle, so a key fingerprint obtained some other way
(for example written down at install time) is the only way to tie the bundle to an installation; the reference verifier takes it as `--trust-key`.

## 5. Timestamp tokens

An anchor may carry `tsa_token_b64`, the DER of an RFC 3161 token (a CMS SignedData, or a whole TimeStampResp from which the token is taken). The token's
messageImprint must be SHA-256 and equal the 32 bytes of the anchor's `anchor_hash`; its `genTime` is the time the service attests. The signature is **checked only
against a certificate the verifier's user supplies** (`--tsa-ca`): the CMS signature must verify with a certificate carried in the token or supplied, that certificate must
chain to a supplied one, be valid at `genTime` and (if it has the extension) allow timestamping. Without a supplied certificate the result is **NOT CHECKED**: the imprint and
time are read, the signature is not checked (reported as "signature not authenticated"). A timestamp attests only to the time of a hash. It covers what existed when that anchor was made.

## 6. Results

Every check prints `PASS`, `FAIL` or `NOT CHECKED`. Exit code 0: no failure and nothing left unchecked. 1: at least one failure. 2: no failure, at least one check could not be made.
3: the input is not a readable bundle. The summary says what was established and what was not, and states "not altered since <time>" only where a token whose signature was checked supports it.

What a clean result does not establish: who exported the bundle; that the events are true or complete (reads, network, MCP calls and short-lived processes are not recorded);
anything about events after the newest anchor or timestamp; anything about alerts, sessions, audit entries or monitoring-gap records, which are not integrity-protected in this version.
