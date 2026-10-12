# Evidence anchoring and signed export: design

Status: design only, no code written. Date: 2026-10-10.
Scope: make the exported report honestly "tamper-evident" against someone who can edit the local database after the fact (the monitored agent, or the user it runs as).
Source read: branch pilot/p1-backend-safety at 15d23e6. The live database was not read; everything below comes from code and schema.

One rule runs through the whole document: **only a hash (32 bytes, plus a few counters) may ever leave the machine.** No event, path, command, alert text or agent name is sent to any anchor target.

---

## 0. Summary of the recommendation

1. Add an anchor record (head hash, event count, anchor sequence number, digest of the report tables, previous anchor hash) every hour and at every export.
2. Timestamp each anchor with an RFC 3161 authority (hash only), queued and retried offline.
3. Sign the export bundle with a per-install Ed25519 key and ship it with a `chain-proof.json` and the events needed to re-walk the chain.
4. Ship a small standalone verifier that trusts nothing from Vigil.
5. Later, bring alerts, dismissals, sessions and coverage under a second append-only "meta chain", and move the backend to a service account so the monitored user cannot touch the key or the DB.

Recommended MVP is stages 1 to 3 below (about 11 working days). Until stage 1 ships, the report must not use the word "tamper-evident" (section 8).

---

## 1. The chain today, exactly

### 1.1 What is hashed

- Table `event_chain` (backend/db/schema.sql:38-44): `id` (autoincrement), `event_id` (UNIQUE, references events), `row_hash`, `prev_hash`, `sealed_at`.
- `compute_row_hash(event_row, prev_hash)` = SHA-256 of `prev_hash + canonical_row_string`, hex (backend/core/evidence_chain.py:65-66).
- `canonical_row_string` joins 14 columns of the `events` row with `|`, each coerced with `str()`, `None` becomes `""`: `id, agent_id, session_id, event_type, path, detail, file_count, data_volume_bytes, severity, anomaly_score, pid, behaviour_score, event_source, created_at` (evidence_chain.py:47-62). This is every column of `events` (schema.sql:14-36).
- No key is involved. Anyone who can run SHA-256 can produce a valid chain.

### 1.2 Genesis and ordering

- Genesis `prev_hash` is the constant `"0" * 64` (evidence_chain.py:23). It is not derived from anything install-specific, so every install starts from the same value.
- Ordering is `events.id ASC`. Sealing resumes from `MAX(event_id)` in `event_chain` (evidence_chain.py:100-107).
- The sealer is a scheduler job every 15 s (backend/main.py:401, function at main.py:444-449). A single run seals at most `SEAL_BATCH_LIMIT = 500` rows (evidence_chain.py:33), so a backlog drains over several cycles.
- Sealing opens its own connection to the same SQLite file (evidence_chain.py:93), so the chain lives in the very file an attacker can edit.

### 1.3 Where the head and sequence are stored

- There is no separate head record. The head is "the `row_hash` of the highest `event_chain.id`" (`get_chain_head`, evidence_chain.py:128-149), together with `COUNT(*)` and `MAX(event_id)`.
- The "sequence" is `event_chain.id`, which is just SQLite autoincrement in the same file.
- Nothing outside the DB file remembers any of these values.

### 1.4 How verification and export use it

- `verify_chain()` (evidence_chain.py:152-242) re-reads every chain row joined to its event and checks, in order: `prev_hash` equals the previous row's `row_hash` (broken_link), the event still exists (event_deleted), and the recomputed hash equals the stored one (hash_mismatch). It stops at the first failure.
- It is called in the PDF export only (backend/api/export.py:548-556) and by `GET` routes in backend/api/chain_routes.py:13-22. **The JSON export does not call it and carries no chain status** (export_json is export.py:485-487 and returns `_build_summary` unchanged).
- The PDF line reads "Evidence chain: VERIFIED INTACT (N events checked)". The verifier is Vigil itself, reading the same DB.

### 1.5 What the chain does not cover

- `alerts` (schema.sql:47-75, including `status`, `resolved_by`, `resolution_note`), `audit_log` (schema.sql:101-109; dismissals and approvals are written at backend/api/alerts.py:156/221/262 and api/agents.py:144/184, with audit rows at alerts.py:166,231,270, agents.py:156,198 and core/alerter.py:148), `policy` (schema.sql:78-83; written at api/agents.py:35 and db/database.py:155), `sessions` (schema.sql:112-132), `vigil_runs` and `monitoring_gaps` (schema.sql:164-187; written by core/monitoring_coverage.py:78,136,198), `app_config` (schema.sql:154-158, holds the webhook URL).
- The export reads those tables directly: coverage from `vigil_runs` and `monitoring_gaps` (export.py:219-290), alerts from `alerts` joined to `agents`.
- Events not yet sealed (up to 500 per 15 s cycle, more during a backlog) are outside the chain until sealed.

### 1.6 What an attacker with DB write access can do undetected

All of these assume the attacker can run SQL against vlaw.db (the monitored agent runs as the same Windows user, and the file sits in `%LOCALAPPDATA%\V-LAW\data`).

1. **Full recompute.** Edit or delete any events, then re-run the same algorithm: rewrite `event_chain` from the first changed row to the end with fresh hashes. `verify_chain()` returns valid. This needs about 20 lines of Python and no secret.
2. **Truncation.** Delete the last K events and the last K `event_chain` rows. The remaining chain is internally perfect. Nothing records that K more rows once existed.
3. **Whole-history replacement.** Replace both tables with a fabricated history from the constant genesis.
4. **Append forged events.** Insert new `events` rows with higher ids. The next seal cycle chains them as if genuine. `created_at` is free text the attacker controls.
5. **Pre-seal edits.** Change or delete an event in the window before it is sealed. There is nothing to compare against.
6. **Alerts, dismissals, policy, sessions, coverage.** Edit them freely. No hash covers them, so `UPDATE alerts SET status='dismissed'`, deleting a red-line alert, or deleting a `monitoring_gaps` row leaves no trace in any check.
7. **Delete or replace the DB file.** A fresh DB starts a new valid chain at genesis. The PDF says "VERIFIED INTACT" for it.
8. **Export file edits.** The PDF and JSON are unsigned plain files.

What is genuinely detected today: a partial, unsophisticated edit that touches an event row without recomputing the rows after it (hash_mismatch), deleting one event or one chain row in the middle (event_deleted, broken_link). That is accident detection, not adversary resistance.

---

## 2. What to anchor

### 2.1 The anchor record

An anchor is a small canonical JSON object. Only its SHA-256 (the `anchor_hash`) is sent to a timestamp or anchor target.

```
{
  "v": 1,
  "install_id": "<random uuid4 created once, stored beside the signing key>",
  "anchor_seq": 17,                       // monotonic, starts at 1
  "prev_anchor_hash": "<hash of anchor 16, or 64 zeros for seq 1>",
  "chain_head": "<event_chain head row_hash>",
  "event_count": 48211,                   // COUNT(*) of event_chain
  "last_event_id": 49002,
  "meta_head": "<head of meta chain, or null before stage 4>",
  "tables_digest": "<see 2.3>",
  "created_at": "2026-10-10T09:00:00Z"    // local clock, informational
}
```

`anchor_hash = SHA-256(canonical JSON, sorted keys, no whitespace)`.

Why each field:

- **chain_head, event_count, last_event_id**: pin the chain at a point in time. Truncation (1.6 item 2) now shows up as a count or head lower than a previously anchored one. Full recompute (item 1) shows up as a different head for the same count.
- **anchor_seq and prev_anchor_hash**: anchors form their own chain. Deleting history, or wiping the DB and restarting, breaks continuity: the next anchor claims seq N+1 with a `prev_anchor_hash` that no longer matches, or the series restarts at 1 under the same `install_id`. A verifier holding any earlier anchor (from the timestamp authority, the customer target, or an earlier bundle) sees the discontinuity.
- **install_id**: lets an external holder tell series apart. It also means "everything deleted including the key" produces a new install_id, which shows up as "series ended at seq N, new series began" at any target that kept the old one (see threat table, section 7).
- **meta_head and tables_digest**: bring the non-event tables under the same umbrella (2.2, 2.3).

The counters `anchor_seq` and `install_id` should be stored in the key directory (section 5), not only in the DB, so deleting vlaw.db alone does not reset them.

### 2.2 Bringing the other tables under the umbrella, with minimal schema change

Two options considered:

**Option A: meta events inside the existing chain.** Insert `events` rows with `event_type = 'meta_alert' | 'meta_dismissal' | ...` and let the existing sealer chain them. No new chain code. Rejected as the main approach: it pollutes the `events` table that the baseline, behaviour detector, session roll-ups, `event_count` in the export and the UI all read, and any reader that does not know about the new types will count them. Changing `_canonical_row_string` is off the table (evidence_chain.py:51-53 says the field set must never change).

**Option B (recommended): a second append-only hash chain.** One new table:

```
meta_chain(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,        -- alert_created | alert_state | audit | policy | session_closed | gap | run
  ref_id TEXT NOT NULL,      -- primary key of the source row
  digest TEXT NOT NULL,      -- SHA-256 of that row's canonical fields at this moment
  prev_hash TEXT NOT NULL,
  row_hash TEXT NOT NULL,    -- sha256(prev_hash + kind + ref_id + digest)
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

A new row is appended each time a covered row is created or changes state. Alerts mutate (status, resolution), so each state change is a new meta row: the chain is an append-only history of states, never an in-place edit. The existing sealer pattern (own connection, batch cap, scheduler job) is reused. The writers listed in 1.5 already sit on a few code paths (alert insert in core/alerter.py, status updates in api/alerts.py and api/agents.py, audit inserts, gap insert in core/monitoring_coverage.py:78), so the hook is a handful of call sites. Anything that is missed is caught by the periodic snapshot digest (2.3).

Cost: one table, one job, about 4 days including tests (section 9). The chain head goes into every anchor as `meta_head`.

### 2.3 Snapshot digest (the stage 1 stand-in)

Before the meta chain exists, each anchor carries `tables_digest`: SHA-256 over the canonical rows of `alerts`, `audit_log`, `sessions`, `monitoring_gaps`, `vigil_runs` and `policy`, each table's rows sorted by primary key, columns in a fixed documented order (same discipline as evidence_chain.py:47-62).

Honest limits: these tables are mutable by design (an alert is dismissed after it was anchored), so a later anchor's digest differs from an earlier one for legitimate reasons, and nobody can recompute a historic digest from the current table. What the snapshot gives:

- The export forces a fresh anchor, so the digest over the exact rows in the report is timestamped at export time. After that the report cannot be altered without detection.
- It does not prove the alert rows were unmodified before the first anchor that covered them. That needs the meta chain (stage 4).

---

## 3. Anchor targets compared

All targets receive only `anchor_hash` (32 bytes) and, for customer-owned targets, the small counters in 2.1 if the customer wants them. None receive events, paths, commands or names.

| | RFC 3161 TSA | OpenTimestamps | Transparency log (Sigstore Rekor) | Customer-owned (webhook, email, file share, git commit) | None, local only |
|---|---|---|---|---|---|
| Trust model | A named TSA signs "this hash existed at time T". Verifiable offline with the TSA certificate. Trust is in the TSA operator. | Hash is committed into Bitcoin via calendar servers. Trust is in Bitcoin, no operator. | Public append-only log; anyone can check inclusion. Trust is in the log operator plus its monitors. | The customer's own system keeps the record. Trust is in the customer. Strongest for the customer's own audit, weak as independent proof to a third party. | Self-attestation only. |
| Cost | Free TSAs exist; commercial ones are cheap per token. Hourly is 24 tokens per day. | Free. | Free public instance. | Free (customer's infra). | Free. |
| Works offline | Needs the network to obtain a token. Verifying an existing token is fully offline. | Needs the network to submit. A proof is incomplete until Bitcoin confirms (typically hours), and checking it needs Bitcoin block headers, i.e. a node or an explorer (network). | Needs the network. Verifying an inclusion proof offline needs the log's signed tree head. | Needs the network or the file share. | Yes. |
| Windows and PyInstaller fit | Good. HTTP POST of a small DER request with `httpx` (already a dependency, backend/requirements.txt:9). Request is a fixed structure and can be built by hand. Parsing the response properly needs ASN.1 (see section 9 dependencies). | Pure Python library exists; submission is plain HTTP. Verification path is heavier. | Needs a signing identity (keyless OIDC flow or own key) and a client library; heaviest to fit offline and in a single exe. | Good. A webhook already exists in the product (`app_config` holds `webhook_url`, schema.sql:154-158). | Trivial. |
| Effort | About 4 days for client, queue and verify. | About 5 days, plus handling "pending until confirmed". | About 6 days and awkward identity handling. | Webhook about 2 days; git commit to a customer repo about 3 days (credential handling). | 0. |
| What leaves the machine | Hash, one network request per anchor, to the TSA. TSA sees the machine's IP and the hash. | Hash to several public calendar servers. | Hash plus the signing identity and public key, recorded in a public log forever. The existence of an entry per install is public. | Hash and counters to a destination the customer chose. | Nothing. |
| Independent of the customer? | Yes. A third party can check it without the customer. | Yes. | Yes. | No. | No. |

Recommendation:

- **Default: RFC 3161 TSA.** Smallest trust and engineering cost, offline verification, independent of the customer, small payload. Support configuring a different TSA URL, and keep a primary and a fallback.
- **Add the customer-owned webhook as a second target** (stage 5). It gives the customer a heartbeat they hold themselves, which is the only thing that notices "Vigil was stopped" (threat table). It reuses the existing webhook.
- **Do not build OpenTimestamps or Rekor in the MVP.** OTS has the unconfirmed-proof wrinkle and a network-dependent verifier. Rekor adds a public identity trail that some customers will not accept.
- **"None, local only" must remain an explicit, labelled mode** (air-gapped customers). In it the report must say so (section 4.3) and the stage 1 claim cannot be used.

---

## 4. Cadence and failure behaviour

### 4.1 When anchors are made

- **Local anchor record** (section 2.1) is created **every hour if the chain head changed**, **at every export**, and **at startup after a monitoring gap** (so a restart is itself pinned). It is created and stored locally whether or not the network works.
- **External timestamp** for each anchor is requested right after creation, and retried as needed.
- Why hourly rather than daily: the window in which an edit can be made without any anchor on record is the anchor interval. Daily leaves 24 hours; hourly leaves up to 1 hour for normal operation. Per-export-only leaves arbitrary time. Hourly costs 24 small requests a day.
- The export always forces an anchor first, so the report is bound to a head and a table digest that exist at that moment.

### 4.2 Queue and retry

New table `evidence_anchors(anchor_seq PK, anchor_json, anchor_hash, status, attempts, next_try_at, tsa_token BLOB, tsa_name, timestamped_at, error)`; `status` is `local_only`, `pending`, `timestamped`, `failed`.

- On network failure: status stays `pending`, `next_try_at` backs off 1 min, 5 min, 30 min, then hourly. Retries survive restarts because the queue is in the table.
- A pending anchor is never dropped. When the network returns, all pending anchors are stamped in order. A late stamp proves the head existed **by** the stamp time, not at the original creation time. The report states the stamp time, not the local creation time, as the proof time.
- A malformed or rejected TSA reply counts as an attempt, is logged, and does not mark the anchor timestamped.
- Failure must never block sealing, exports or the rest of the backend; it only changes what the report says.

### 4.3 What the report says

Always printed (PDF section "Evidence integrity", and in `chain-proof.json` and the JSON export as structured fields):

- `Last anchor: 2026-10-10 09:00 (seq 17), status: timestamped by <TSA name> at 09:00:04`
- `Anchors in this report period: 24 of 24 timestamped`
- Chain line: `Evidence chain: consistent, N events, head <first 12 hex>`.

When things are missing or wrong, exact wording:

- Some pending: `Last anchor: <time> (seq N), status: waiting for timestamp since <time> (no network). Events recorded after the last timestamped anchor (<time>) are not yet externally protected.`
- No anchors at all (local-only mode or never reached a TSA): `Anchoring: none. The chain is consistent but is stored only on this machine; this report cannot show that earlier records were not altered.`
- Gap in the series: `Anchor continuity: BREAK between seq 12 and seq 14` (verifier-style failure line).
- Chain failure: unchanged `INTEGRITY FAILURE: <reason>` (export.py:551).
- A missing-anchor line must never be omitted or softened to "OK". Absence is printed as absence.

---

## 5. Signed export

### 5.1 Key

- Per-install Ed25519 key pair, generated at first run. The `cryptography` package already provides Ed25519 (`cryptography.hazmat.primitives.asymmetric.ed25519`); it is already a dependency (backend/requirements.txt:10) and is used for license signature checks (backend/license/license_service.py:27-29). It is not named in the spec's hidden imports (vlaw-backend.spec:11-58) but is statically imported by the license module, so it is already inside the existing exe. This is an inference from the import and the working license check; confirm with a throwaway build before relying on it.
- Storage: private key in `%LOCALAPPDATA%\V-LAW\keys\install.key`, protected with Windows DPAPI (`CryptProtectData` through `ctypes`, no new dependency), user scope. Public key and `install_id` in `install.pub.json` beside it. The key directory is separate from `data\` so wiping the DB does not reset the identity, the key and the anchor counter.
- Fallback if DPAPI is unavailable: file with owner-only ACL, with a warning in the log and the report ("key not hardware or OS protected").
- The public key fingerprint should be registered out of band at install time (shown in the UI, recorded by the customer, or sent to the customer webhook once). A verifier that trusts whichever key arrives in the bundle proves nothing.

### 5.2 What the signature proves, and what it does not

Because the backend, and the agent it monitors, run as the same Windows user, DPAPI user-scope gives **no** protection from that user: any process in that session can call `CryptUnprotectData` on the key blob.

The signature proves:

- The bundle contents (report.pdf, report.json, chain-proof.json, events file) are exactly what some holder of this install's private key signed. Edits to the files after signing are detected, so the **export file replacement** attack fails.
- Combined with anchors: the signed anchors existed by their stamp times.

The signature does **not** prove:

- That the data was true or complete. Whatever was in the DB at export time was signed, including forged alerts inserted before export.
- That the key was not used by someone else. A process running as the same user can load the key and sign a forged bundle. It could not, however, change what a TSA already stamped or what a customer already holds.
- That Vigil was running the whole time, or saw everything. Events never observed are never recorded (30 s process polling, report note in backend/api/export.py REPORT_NOTES).

So: the signature is good against casual or after-the-fact editing of the exported files and gives a stable identity for the series; **the external anchors, not the signature, are what constrain a same-user adversary.**

### 5.3 Bundle format

A zip, `vigil-evidence-<install_id8>-<date>.zip`:

```
report.pdf             the PDF, unchanged format plus the "Evidence integrity" section
report.json            the existing JSON export, now including chain status and anchor status
events.jsonl           canonical event rows (all 14 hashed columns) from just after the
                       last anchor that precedes the report period, through the export anchor
chain-proof.json       see below
chain-proof.sig        Ed25519 signature over chain-proof.json (detached)
```

`chain-proof.json`:

```
{
  "v": 1,
  "install_id": "...",
  "public_key": "<base64 ed25519 public key>",
  "public_key_fingerprint": "<sha256 of key, hex>",
  "generated_at": "...",
  "period": {"start": "...", "end": "..."},
  "files": {"report.pdf": "<sha256>", "report.json": "<sha256>", "events.jsonl": "<sha256>"},
  "chain": {"genesis": "000...", "first_prev_hash": "...", "head": "...", "event_count": N, "last_event_id": M},
  "meta": {"head": null | "...", "tables_digest": "..."},
  "anchors": [ {anchor_json..., "anchor_hash": "...", "status": "timestamped",
                "tsa_name": "...", "tsa_token_b64": "..."} , ... ],
  "limits": ["events outside this period are covered only by anchor continuity", "..."]
}
```

`events.jsonl` is what makes offline chain checking possible: the verifier re-walks the rows from a `first_prev_hash` that must equal the `chain_head` of an anchor earlier than the period (or the genesis), up to the head of the export anchor. Size is the open cost: roughly the day's events, tens of MB at the high end uncompressed, a few MB zipped. Hourly anchors keep the segment bounded to the period plus at most one hour.

### 5.4 Stronger later: a separate service account

Run the backend as a Windows service under a dedicated or virtual account, with:

- The DB, key directory and log in `%ProgramData%\Vigil\` with an ACL that gives the interactive user read-only (or no) access.
- The key in DPAPI machine scope or an ACL-restricted file that only the service account can read.
- The tray talks to the backend over the existing localhost API only.

Then an agent running as the user can no longer write the DB or read the key, which turns most rows of the threat table from "detected after the fact" into "prevented". It does not help against a local administrator. This is a real installer and permissions project (about 8 to 10 days), not part of the MVP, and not something to claim before it exists.

---

## 6. Offline verifier

### 6.1 Form

A separate, small, readable program: `vigil-verify` (Python script of roughly 400 lines using only `hashlib`, `json`, `zipfile` and `cryptography`), also built as a single exe with PyInstaller. It is deliberately **not** a mode of vlaw-backend.exe: "without trusting Vigil" means different code, published as source so an auditor can read it. It never opens vlaw.db and never contacts Vigil.

### 6.2 Inputs

```
vigil-verify <bundle.zip | bundle-dir>
             [--trust-key <fingerprint-or-pubkey-file>]   pinned key from an out-of-band source
             [--tsa-ca <pem>]                              trusted CA certs for TSA tokens
             [--earlier-anchor <anchor.json>] ...          anchors held independently (customer webhook, older bundle)
             [--json]                                      machine-readable output
```

No network access by default. (An optional `--online` could re-fetch nothing sensitive; it is not required and not part of the MVP.)

### 6.3 Checks and result lines

Each check prints exactly one line, `OK`, `FAIL`, `WARN` or `SKIP`:

| Line | Meaning |
|---|---|
| `FILES ok` / `FILES FAIL <name>` | Every file in `chain-proof.json` hashes to the listed SHA-256. FAIL means report.pdf, report.json or events.jsonl was changed after signing. |
| `SIGNATURE ok` / `SIGNATURE FAIL` | The detached signature verifies against the public key in the proof. FAIL means chain-proof.json itself was altered. |
| `KEY pinned` / `KEY UNPINNED` / `KEY MISMATCH` | The key in the bundle matches the key you supplied with `--trust-key` / you supplied none, so the signature only proves internal consistency / the key differs from the one you trust (FAIL). |
| `CHAIN ok (N events, head xxxx)` / `CHAIN FAIL at event_id=X` | Re-walked every row of events.jsonl with the same canonical string and SHA-256, from `first_prev_hash`, and reached the claimed head with the claimed count. FAIL gives the first bad event id and the reason (broken link, hash mismatch, wrong count, head differs). |
| `ANCHOR-LINK ok` / `ANCHOR-LINK FAIL` | `first_prev_hash` equals the chain head recorded in the earlier anchor, and the export anchor's head and count equal the chain just computed. FAIL means the events segment is not the one the anchors attest to. |
| `ANCHORS continuity ok (seq a..b)` / `ANCHORS BREAK between seq x and y` | `prev_anchor_hash` links hold, `anchor_seq` is consecutive, `event_count` and `last_event_id` never decrease. BREAK is what a truncation or a deleted-and-restarted DB looks like. |
| `TIMESTAMP seq n ok <TSA> <time>` / `TIMESTAMP seq n UNVERIFIED (no --tsa-ca)` / `TIMESTAMP seq n FAIL` | The TSA token's imprint equals `anchor_hash` and its signature verifies to a trusted CA. UNVERIFIED means the token is present but could not be checked here. FAIL means mismatch or bad signature. |
| `TIMESTAMP seq n PENDING` | The anchor was never timestamped (no network at the time). The claim for this anchor is local only. |
| `EARLIER-ANCHOR ok` / `EARLIER-ANCHOR FAIL` | Each anchor supplied with `--earlier-anchor` is consistent with this chain (its head is an ancestor in the bundle, or its count is not above this chain's). FAIL is the strongest finding: history was rewritten after that anchor was held elsewhere. |
| `META ok` / `META SKIP` | Meta chain and table digest checks (stage 4); SKIP before it exists. |
| `COVERAGE info` | Prints the last anchor time, timestamped fraction, and the period start. Informational only; never turns the result green or red. |

### 6.4 Exit codes

- `0`: all checks passed with nothing worse than informational lines. Printing `RESULT: CONSISTENT` plus the explicit scope sentence ("events up to <last timestamped anchor time> were not altered since that time").
- `1`: at least one FAIL. Prints `RESULT: TAMPERING OR CORRUPTION DETECTED` and lists the failures.
- `2`: no FAIL but the result is weak: any `UNPINNED`, `UNVERIFIED`, `PENDING`, missing anchors or `SKIP`. Prints `RESULT: INCONCLUSIVE` and why. This keeps "we could not check" from looking like success.
- `3`: bad input (not a bundle, unsupported version, unreadable file).

`--json` outputs the same results as a list of `{check, status, detail}` plus `exit_code`.

---

## 7. Threat table

"Detected" means detectable by the verifier (or the report) by someone who did not trust the machine. Stage columns are cumulative.

| Attacker action | Today | Stage 1: local anchors + export forces anchor + bundle | Stage 2: RFC 3161 timestamps | Stage 3: signed bundle + verifier | Stage 4/5: meta chain, customer webhook | Stage 6: service account |
|---|---|---|---|---|---|---|
| Edit/delete an event before the next anchor (still unsealed or between anchors) | Not detected (also nothing to compare) | Not detected | Not detected for changes made before the next anchor. The exposure window is the anchor interval (1 h) | Same | Same; the webhook heartbeat shortens nothing but narrows who can silently do it | Prevented for the user account |
| Edit/delete an event after an anchor, then recompute the chain | Not detected | Detected only if the verifier holds an earlier anchor (e.g. from an older bundle) | **Detected**: recomputed head differs from the timestamped head | Detected, and the verifier tells you which anchor | Detected | Prevented |
| Truncate the tail (delete last K events and chain rows) | Not detected | Detected if an earlier anchor is held (count lower) | **Detected** (count lower than a stamped anchor) | Detected | Detected | Prevented |
| Delete or replace the DB (fresh chain) | Not detected; report says INTACT | Detected on next export if the key dir kept the `anchor_seq` (series continuity), not if both are wiped | Detected for the stamped anchors held by the TSA/customer: series restarts. If key dir is also wiped it appears as a new `install_id`; the old series simply stops (visible only to whoever kept the old anchors) | Same | The customer's webhook shows "series ended at seq N, new install_id appeared" | Prevented (ACL) |
| Stop Vigil / block it | Detected only as a coverage gap in the same editable DB | Same | Anchor series stops hourly, visible to anyone looking at timestamps; the report's own `Last anchor` line is stale | Same | **Detected by the customer**: heartbeat stops | Service restart policy and tamper protection |
| Replace the export file (edit PDF/JSON) | Not detected | Detected if the verifier compares against a bundle hash held elsewhere | Same | **Detected**: signature and file hashes fail | Detected | Detected |
| Forge or delete alerts, change dismissals | Not detected | Snapshot digest binds the alert rows **at export time**; edits before the first anchor covering them stay undetected | Same as stage 1 plus timestamp on the digest | Same | **Detected**: meta chain history shows the alert's creation and each state change; a missing or altered alert breaks it against an anchored `meta_head` | Prevented |
| Suppress anchoring (block the network) | n/a | n/a | Anchors stay `pending`; report and verifier say PENDING/INCONCLUSIVE, never OK | Same | The customer webhook goes silent | Same |
| Use the signing key to sign a forged bundle | n/a | n/a | n/a | **Not detected by the signature**, same-user key. Still constrained by timestamped anchors: a forged chain cannot match stamped heads | Same | Key not readable by the user account |
| Forge events that are never recorded (the watchers never saw them) | Not detectable | Not detectable | Not detectable | Not detectable | Not detectable | Not detectable |

The last row is a hard limit and belongs in the sales language (section 8): this design proves records were not altered, not that the records are complete.

---

## 8. Claim language

One rule for all stages: the word "tamper-proof" is never used; "tamper-evident" is used only with the scope in the same sentence.

### 8.1 Today (unkeyed chain, no anchors, unsigned export)

May say (report and sales):
- "Events are recorded in a hash chain, and the report states whether the stored chain is internally consistent."
- "Detects accidental corruption and simple edits to stored records."

Must NOT say:
- "Tamper-evident", "tamper-proof", "immutable", "cryptographically verified", "audit-grade", "cannot be altered", "evidence that stands up in court."
- The current PDF wording "VERIFIED INTACT" (export.py:551) overstates this; change it to "Chain internally consistent" no later than stage 1.

### 8.2 Anchored (stage 1 and 2)

May say:
- "The chain head is timestamped by an independent time-stamping authority every hour. Any change to events recorded before the last timestamped anchor, including deleting them or rewriting the chain, can be detected by comparing against that timestamp."
- Report line: "Records up to <time of last timestamped anchor> are protected by an external timestamp (seq N)."

Must NOT say:
- "The report cannot be altered" (the file is not signed yet).
- "Everything in this report is protected" (events after the last anchor, and until stage 4 the alert, dismissal and coverage rows, are not protected before the first anchor that covered them).
- "Independent of the customer" for the customer-webhook anchor; "third party verified" for local-only mode.

### 8.3 Anchored plus signed (stage 3, with verifier)

May say:
- "This report is signed by installation <fingerprint> and any change to it after export is detected. A standalone verifier checks the signature, the evidence chain and the external timestamps without trusting Vigil."
- "Events recorded before <time> cannot be altered undetected."

Must NOT say:
- "Cannot be forged by the monitored user or agent." (Same Windows user can read the key; true only after stage 6.)
- "Proves what the agent did", "complete record of agent activity." (Polling gaps, unwatched events, and the 30 s program check; the report's own notes say so.)
- "Verified by <TSA>": the TSA attests only to time of a hash, not to content.

After stage 6 an additional sentence is allowed, scoped to the configuration: "When Vigil runs as a service account, the monitored user's own processes cannot modify the evidence store or read the signing key." Not for local administrators.

---

## 9. Staged plan, effort, risk, dependencies, tests

### 9.1 Stages (days are working days of one engineer, including tests)

| Stage | Content | Days |
|---|---|---|
| 1 | `evidence_anchors` table; anchor record (2.1) incl. snapshot `tables_digest` (2.3); hourly, at export, at post-gap startup; anchor counter and `install_id` stored in the key dir; JSON export gains chain and anchor status; PDF "Evidence integrity" section and wording change; honest wording for missing anchors (4.3) | 2 |
| 2 | RFC 3161 client (hash-only request, retry queue, backoff, token stored); primary and fallback TSA setting; status in report | 4 |
| 3 | Ed25519 key in DPAPI; bundle zip (5.3) incl. `events.jsonl`; `vigil-verify` (section 6) and its tests; docs for pinning the key | 5 |
| 4 | `meta_chain` (2.2), hooks at the writer call sites, `meta_head` in anchors, verifier META checks | 4 |
| 5 | Customer webhook anchor and heartbeat (reuse `webhook_url`); git-commit target optional later | 2 |
| 6 | Service-account deployment and ACLs | 8 to 10 |

**Recommended MVP: stages 1 to 3, about 11 days.** It changes the strongest claim from "internally consistent" to "protected against rewrite since the last external timestamp, with an independent verifier". Stage 5 is cheap and should follow immediately because it is the only thing that notices a stopped backend. Stage 4 is needed before claiming protection for alerts and dismissals. Stage 6 is only worth building if customers need protection from the monitored user itself.

### 9.2 Risks

- **Report size and speed**: `events.jsonl` for a busy day may be large; mitigate with hourly anchors and zip. Chain walks already cost real time (evidence_chain.py:152-242 comment); the verifier is a separate process so it does not touch the event loop.
- **Canonical form lock-in**: the field order in `_canonical_row_string` (evidence_chain.py:47-62) can never change once anchored. Document it as a versioned format (`v: 1`) and make the verifier carry its own copy; any future format gets a new version and a new chain segment.
- **Clock**: anchor `created_at` is the local clock; only the TSA time is trusted. Report must say so (4.2).
- **Pending/offline machines** get weaker claims by design; the report wording is the safeguard, so it must be tested (9.4).
- **Key loss or reinstall**: a new key means a new `install_id` and a visible series break. Provide a documented "key rotation" anchor that the old key signs, and state that a clean reinstall looks like a new series.
- **Privacy review**: the TSA sees the hash and source IP only. The Rekor option would publish an identity; not in the MVP for that reason.
- **Over-claiming** is the main business risk. Section 8 wording should be reviewed before any marketing text changes.

### 9.3 New dependencies and bundle-size cost

(Sizes are estimates; measure with a real build before committing.)

| Need | Choice | New to the backend exe? | Estimated size cost |
|---|---|---|---|
| SHA-256, JSON, zip | stdlib | No | 0 |
| Ed25519 | `cryptography` (already requirements.txt:10, used in license_service.py:27-29) | No | 0 |
| HTTP to TSA | `httpx` (already requirements.txt:9) | No | 0 |
| DPAPI | `ctypes` (stdlib) | No | 0 |
| Building the RFC 3161 request | hand-built DER (a fixed structure of a few dozen bytes) | No | 0 |
| Parsing and verifying the TSA response (CMS SignedData) | `asn1crypto` (pure Python) in the **verifier**; the backend only needs to check status granted and the message imprint, which can also be done with a small DER walk | Verifier only; backend optional | About 0.5 to 1 MB (estimate) |
| Verifier executable | PyInstaller single file with `cryptography` | Separate artifact | Roughly 15 to 20 MB because of `cryptography`'s native library (estimate); a Python script distribution avoids it |
| OpenTimestamps / Rekor clients | Not in the MVP | n/a | n/a |

Net effect on vlaw-backend.exe (currently about 40 MB, from the last two builds): close to zero for stages 1 to 3 if the verifier lives in its own artifact and the backend does not parse CMS.

### 9.4 Test plan

Unit and integration tests, in the existing `backend/tests` style (fresh `VLAW_DATA_DIR` per run):

1. **Anchor record**: canonical JSON is stable (golden hash for a fixed input), `anchor_seq` increments, `prev_anchor_hash` links, counter survives deleting vlaw.db when the key dir is kept.
2. **Cadence**: head unchanged means no new hourly anchor; export always creates one; post-gap startup creates one.
3. **Queue and retry** with a fake TSA transport: success; HTTP error leaves `pending` and backs off; restart resumes pending; malformed reply is not marked timestamped; a late stamp reports the stamp time.
4. **Report wording**: parametrised test that renders the PDF/JSON for each state (timestamped, pending, none/local-only, continuity break, chain failure) and asserts the exact lines from 4.3, and that the string "tamper-proof" never appears.
5. **Bundle and signature**: bundle contains all five files; flipping one byte in report.pdf, report.json, events.jsonl or chain-proof.json each yields `FILES FAIL` or `SIGNATURE FAIL` and exit 1.
6. **The rewrite test (required)**: build a DB with N events, seal, create and (fake-)timestamp an anchor A. Then simulate the attacker: edit one event, **recompute the whole `event_chain` with the same algorithm** so Vigil's own `verify_chain()` returns valid, export a bundle. Assert: Vigil's `verify_chain()` says valid (proving the old check is blind to this), but `vigil-verify` with `--earlier-anchor A` (and, separately, a bundle whose `anchors` include A) exits 1 with `ANCHORS`/`EARLIER-ANCHOR FAIL`, naming the head mismatch. A variant truncates the last K events and chain rows and asserts the count-decrease finding. A third variant deletes vlaw.db entirely, restarts, exports, and asserts `ANCHORS BREAK` (key dir kept) and `install_id` change (key dir also wiped).
7. **Verifier exit codes**: bad zip is 3; no `--trust-key` or no `--tsa-ca` gives 2 with UNPINNED/UNVERIFIED; pending anchors give 2; all good gives 0.
8. **Stage 4 only**: delete or alter an alert row after its meta row is anchored, assert `META FAIL`; legitimate dismissal appends a new state row and verifies clean.
9. **Frozen build smoke** (manual, once per release): a PyInstaller build produces a bundle and the standalone verifier accepts it; confirms `cryptography` Ed25519 is present in the frozen exe.

---

## 10. Open questions

1. Which TSA is acceptable to customers (a free public one, a commercial one, or customer-hosted)? Default needs a decision before stage 2.
2. Should the bundle include all events for the period, or only a Merkle-style subset? Full rows are simpler to verify; size should be measured on real data (reading a copy of a live DB with its -wal and -shm files would answer this).
3. How is the public key fingerprint delivered out of band at install time (installer prompt, customer webhook first message, printed in the UI)?
4. Is local-only mode a supported product tier, and if so what is its permitted claim (section 8.1 wording only)?
5. Does any customer require protection from local administrators? If so, stage 6 is not enough and a remote anchor target held by the customer becomes mandatory.
