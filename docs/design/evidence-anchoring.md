# Evidence anchoring and signed export: design

Status: design. Stage 1 (local anchors, section 11) is implemented as of 2026-10-14, Stage 2 (opt-in external timestamps, section 13) and Stage 3 (signed bundle and offline verifier, section 14) as of 2026-10-15; stages 4 to 6 are design only. Date: 2026-10-10, updated 2026-10-14.
Scope: make the exported report honestly "tamper-evident" against someone who can edit the local database after the fact (the monitored agent, or the user it runs as).
Source read: branch pilot/p1-backend-safety at 15d23e6; the line numbers in section 1 were refreshed on 2026-10-14 after Stage 1 (section 11 lists what changed). The live database was not read; everything below comes from code and schema.

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
- The sealer is a scheduler job every 15 s (backend/main.py:442, function `_seal_evidence_chain` at main.py:514). A single run seals at most `SEAL_BATCH_LIMIT = 500` rows (evidence_chain.py:33), so a backlog drains over several cycles.
- Sealing opens its own connection to the same SQLite file (evidence_chain.py:93), so the chain lives in the very file an attacker can edit.

### 1.3 Where the head and sequence are stored

- There is no separate head record. The head is "the `row_hash` of the highest `event_chain.id`" (`get_chain_head`, evidence_chain.py:128-168), together with `COUNT(*)` and `MAX(event_id)`.
- The "sequence" is `event_chain.id`, which is just SQLite autoincrement in the same file.
- Nothing outside the DB file remembers any of these values.

### 1.4 How verification and export use it

- `_verify_chain_internal()` (evidence_chain.py:170-264) re-reads every chain row joined to its event and checks, in order: `prev_hash` equals the previous row's `row_hash` (broken_link), the event still exists (event_deleted), and the recomputed hash equals the stored one (hash_mismatch). It stops at the first failure.
- It is called by both exports, through `_chain_verification()` (backend/api/export.py:680), and by `GET` routes in backend/api/chain_routes.py:13-22. The JSON export carries `chain_verification` (export_json, export.py:776). This corrects the first version of this document, which said the JSON export carried no chain status; that changed before Stage 1 and Stage 1 extended it. Since Stage 1, `verify_chain()` (evidence_chain.py:266) wraps the internal walk and also checks every stored local anchor (section 11).
- The original PDF line read "Evidence chain: VERIFIED INTACT (N events checked)". That wording was replaced before Stage 1 ("consistent ... Checked by Vigil itself; not yet independently anchored"), and Stage 1 replaced it again with the section 4.3 lines (export.py `_chain_lines`, line 728). The verifier is still Vigil itself, reading the same DB.

### 1.5 What the chain does not cover

- `alerts` (schema.sql:47-75, including `status`, `resolved_by`, `resolution_note`), `audit_log` (schema.sql:101-109; dismissals and approvals are written at backend/api/alerts.py:156/221/262 and api/agents.py:144/184, with audit rows at alerts.py:166,231,270, agents.py:156,198 and core/alerter.py:148), `policy` (schema.sql:78-83; written at api/agents.py:35 and db/database.py:155), `sessions` (schema.sql:112-132), `vigil_runs` and `monitoring_gaps` (schema.sql:164-187; written by core/monitoring_coverage.py:78,136,198), `app_config` (schema.sql:154-158, holds the webhook URL).
- The export reads those tables directly: coverage from `vigil_runs` and `monitoring_gaps` (`_compute_coverage`, export.py:302-379), alerts from `alerts` joined to `agents`.
- Events not yet sealed (up to 500 per 15 s cycle, more during a backlog) are outside the chain until sealed.

### 1.6 What an attacker with DB write access can do undetected

All of these assume the attacker can run SQL against vlaw.db (the monitored agent runs as the same Windows user, and the file sits in `%LOCALAPPDATA%\V-LAW\data`).

1. **Full recompute.** Edit or delete any events, then re-run the same algorithm: rewrite `event_chain` from the first changed row to the end with fresh hashes. `verify_chain()` returns valid. This needs about 20 lines of Python and no secret.
2. **Truncation.** Delete the last K events and the last K `event_chain` rows. The remaining chain is internally perfect. Nothing records that K more rows once existed.
3. **Whole-history replacement.** Replace both tables with a fabricated history from the constant genesis.
4. **Append forged events.** Insert new `events` rows with higher ids. The next seal cycle chains them as if genuine. `created_at` is free text the attacker controls.
5. **Pre-seal edits.** Change or delete an event in the window before it is sealed. There is nothing to compare against.
6. **Alerts, dismissals, policy, sessions, coverage.** Edit them freely. No hash covers them, so `UPDATE alerts SET status='dismissed'`, deleting a red-line alert, or deleting a `monitoring_gaps` row leaves no trace in any check.
7. **Delete or replace the DB file.** A fresh DB starts a new valid chain at genesis. Before Stage 1 nothing recorded that an earlier chain had existed, so the report said the chain was fine. With Stage 1 the key directory keeps the anchor counter, and the report shows "Anchor continuity: BREAK" (series restarted); an attacker who also edits the key directory is not caught (section 12).
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
- **meta_head and tables_digest**: intended to bring the non-event tables under the same umbrella (2.2, 2.3). In Stage 1 `meta_head` is null and `tables_digest` is recorded but not verified, so those tables are not protected yet.

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

- The export forces a fresh anchor, so the digest over the exact rows in the report is recorded at export time.
- It does not prove the alert rows were unmodified before the first anchor that covered them. That needs the meta chain (stage 4).

**Status as built: `tables_digest` is recorded but not yet verified.** `check_anchors()` never compares it, so in Stage 1 these six tables are not integrity-protected; only the events table is (hash chain). The reason is the one above: these tables change legitimately (an alert is dismissed, a session closes, a gap is appended), so a stored digest and the digest of the table today differ for ordinary reasons, and a comparison cannot tell a legitimate change from an edit. Telling them apart needs the meta chain (stage 4), which records each legitimate change as it happens.

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
- The export always forces an anchor first, so the report is bound to a head that exists at that moment, and a table digest is recorded with it (recorded, not verified, in Stage 1).

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
- Chain failure: `Evidence chain: INCONSISTENT at event <id>. Do not rely on this report.` (export.py `_chain_lines`). The first version of this document called it `INTEGRITY FAILURE: <reason>`; the wording changed before Stage 1 and Stage 1 kept the current one.
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
| Forge or delete alerts, change dismissals | Not detected | Not detected: the snapshot digest is recorded at export time but not verified in Stage 1 | Same as stage 1 plus timestamp on the digest | Same | **Detected**: meta chain history shows the alert's creation and each state change; a missing or altered alert breaks it against an anchored `meta_head` | Prevented |
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
- The old PDF wording "VERIFIED INTACT" overstated this and has been replaced (done before Stage 1; the Stage 1 wording is in section 11).

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

- **Report size and speed**: `events.jsonl` for a busy day may be large; mitigate with hourly anchors and zip. Chain walks already cost real time (evidence_chain.py:170-264 comment); the verifier is a separate process so it does not touch the event loop.
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

---

## 11. Stage 1 as built (2026-10-14)

What shipped: local anchors only. Nothing leaves the machine and nothing here is an external timestamp.

- **Table** `evidence_anchors` (backend/db/schema.sql:197): `anchor_seq` (primary key), `anchor_json`, `anchor_hash`, `prev_anchor_hash`, `chain_head`, `event_count`, `last_event_id`, `tables_digest`, `install_id`, `created_at`, `trigger` (`hourly`, `export` or `startup_gap`) and `status` (`local_only`). It is created with `IF NOT EXISTS` from schema.sql, the existing mechanism, so an existing database gains the table with no change to any existing row, and an empty database works. The Stage 2 columns (attempts, next_try_at, tsa_token and so on) are not there yet and will be added with `ALTER TABLE` in `_migrate`.
- **Anchor record** (backend/core/evidence_anchor.py): the JSON of section 2.1 with `meta_head` null. `anchor_hash` is the SHA-256 of the canonical JSON (sorted keys, no whitespace).
- **Key directory**: `anchor-state.json` in `VLAW_KEY_DIR` (set by main.py to the folder `keys` next to the data directory, `%LOCALAPPDATA%\V-LAW\keys` when installed) holds `install_id`, the sequence counter and the last anchor hash. Deleting `vlaw.db` does not reset it; the next anchor continues from the remembered counter.
- **When anchors are made**: hourly, only if the chain head or count changed since the last anchor and at least 55 minutes have passed (scheduler job `evidence_anchor`, main.py:445); at every export; and at startup after a monitoring gap (`_anchor_after_gap`, main.py:500). There is no shutdown anchor: the tray force-ends the backend, so a clean shutdown cannot be relied on.
- **Digest of the other tables**: SHA-256 over `alerts`, `audit_log`, `sessions`, `monitoring_gaps`, `vigil_runs` and `policy`, in that order, each table's rows in rowid order (primary-key order for the integer-keyed tables; insertion order for `sessions` and `policy`), columns in `SELECT *` order, one JSON array per row. Because these tables change legitimately, only the digest taken at export time is meaningful to a reader; it does not prove rows were unmodified before the first anchor that covered them. **The digest is recorded but not yet verified:** `check_anchors()` never compares it, because a legitimate change cannot be told apart from an edit without the meta chain (stage 4). So alerts, sessions, audit entries, monitoring gaps, runs and policy are not integrity-protected in Stage 1; only the events table is.
- **Local check** (`verify_chain()`, evidence_chain.py:266, and `check_anchors()`): every stored anchor is compared with the chain as it is now. Result states: `inconsistent` (the chain disagrees with itself), `disagrees_with_local_anchor` (consistent, but a different hash at an anchored event), `shorter_than_local_anchor` (fewer sealed events than an anchor recorded, which is what truncation looks like), and `anchor_continuity_break` (the anchor series is broken: `series_restarted`, `history_missing`, `link_broken`, `install_changed` or `state_missing`). `valid` is False for all of them.
- **Report wording** (export.py `_chain_lines`, line 728): the section 4.3 lines. With no external anchor, which is every case in Stage 1, the report prints `Anchoring: none. The chain is consistent but is stored only on this machine; this report cannot show that earlier records were not altered.` Local anchors are shown on a separate line, marked `local only, no external timestamp`. When no anchor was checked, `anchors_mismatched` is null in the JSON and no mismatch count is printed, so "0 mismatches" is never shown as a pass.
- **JSON export** `chain_verification` gained: `head_hash`, `sealed_count`, `unsealed_count`, `anchoring`, `last_anchor` (`time`, `anchor_seq`, `position`, `head`, `status`), `anchors_checked`, `anchors_mismatched`, `anchor_continuity` and `anchor_problem`. `GET /api/evidence/chain/head` returns `last_anchor` and `anchoring` too.

Deviations from sections 2 to 4 of this document, and why:

1. **Export anchors are reused when nothing changed.** Section 4.1 says every export forces an anchor. The Export page fetches the JSON on every page load and date change, so a literal reading would add a row per preview. An export anchors only when the chain head, the sealed count or the tables digest differs from the last anchor; otherwise the last anchor, which already pins exactly this state, is the one the report cites.
2. **No `status`/queue columns for Stage 2 yet**, as above.
3. **The "Evidence integrity" lines** are printed in the PDF header block and in the JSON, not as a separate titled section.
4. **Digest order** is rowid, not sorted primary key (the two agree for the integer-keyed tables).
5. **Seal before anchor**: an export seals pending events first so the anchor is as current as possible; unsealed events are reported (`unsealed_count`).
6. **Page loads do not run the check.** The Export page fetches the JSON on every load and date change, and a full check measured 0.3 s at 20,000 events and 5,000 rows in each of alerts, audit_log and sessions, and 1.4 s at 50,000 events and 50,000 rows each. `GET /export/json?preview=true` therefore returns the last verification with an `as_of` time (`cached: true`), or `status: "not_checked"` with the cheap facts (head, counts, last anchor) when none has been made since Vigil started. It seals nothing, computes no digest and records no anchor. Downloads (the PDF, and `/export/json` without `preview`) run the full check and record or reuse an anchor, and refresh the remembered result; so does the hourly job. A cached "consistent" is always printed with the time it was true, and a preview never says "consistent" without a check behind it.
7. **Crash-safe key directory write.** The key directory first records the anchor about to be added as pending, then the row is committed, then the committed fields advance and the pending marker is cleared. A crash between the steps leaves either a pending anchor the database never got (ignored; the next anchor reuses the number) or a database one anchor ahead of the key directory (accepted). Neither is reported as tampering, and the sequence stays monotonic with no repeated `anchor_seq`.

Measured cost (synthetic chain of 50,000 events, 2026-10-14, one machine, SQLite on SSD): reading the head and count 0.6 ms; creating an anchor 15 to 33 ms in total (insert, commit and the key-directory file write dominate); a full re-walk of the chain, which anchoring never does, 0.7 to 0.8 s. The tables digest is linear in the rows of the six tables: 3,000 rows in total 27 ms, 30,000 rows 180 ms, 150,000 rows 1.1 s, 600,000 rows 3.8 s. Checking 9,011 stored anchors (about a year of hourly anchors) takes 136 ms.

## 12. Stage 1 limits

### Deleting vlaw.db alone is reported by design

The key directory (`%LOCALAPPDATA%\V-LAW\keys`, next to the `data` folder) keeps the anchor counter, the install id and the hash of the last anchor. If the database is deleted or replaced and the key directory is not, Vigil reports `Anchor continuity: BREAK` (series restarted), and after new anchors are made, `history missing`. That is the intended behaviour: it is exactly what a quietly replaced database looks like, and Vigil cannot tell an attack from a careless delete.

A legitimate reset removes both together, with Vigil stopped:
- Uninstalling and answering Yes to "delete everything Vigil stored" removes the whole `%LOCALAPPDATA%\V-LAW` folder, key directory included (the uninstaller also names the keys folder explicitly). A later install starts a new series with no failure state.
- By hand: stop Vigil, then delete `vlaw.db` (with its `-wal` and `-shm` files) and the `keys` folder together.
- Answering No keeps the database and the key directory, so a reinstall continues the same series.
- A database with events but no key directory (a fresh install over an old database, or a version from before anchors) is not flagged: the first anchor starts the series, and until then the report says `Anchoring: none`.

### What local anchors do not do

Local anchors do not constrain someone who can write the same database. The database, the key directory and the process that makes anchors all run as the Windows user that also runs the monitored agent, so an attacker with that access can edit events, recompute the chain, rebuild the anchors table and update `anchor-state.json` to match, and Vigil's own check then reports a consistent chain. That case is pinned down by the test `test_stage1_does_not_constrain_attacker_who_rewrites_anchors` (backend/tests/test_evidence_anchor.py). What Stage 1 does catch: an edit that does not also rewrite the anchors and the key directory record (a recomputed chain alone, a truncation, a deleted or replaced database, deleted or edited anchor rows), because those leave the three places disagreeing.

An anchor that exists only on this machine is not independent evidence. Stage 2, an external timestamp of each anchor's hash by a party the attacker does not control, is what removes that limit: after it, a rewrite has to match an anchor that was recorded elsewhere. Until Stage 2 ships the report says `Anchoring: none` and must not claim more (section 8). Other limits that remain: events between anchors are not pinned until the next anchor (up to about one hour); the alert, dismissal, policy, session and coverage rows are not protected (the digest taken at each anchor is recorded but never verified); and the digest cannot show those rows were unmodified before the first anchor that covered them (stage 4, the meta chain, addresses that).

## 13. Stage 2 as built (2026-10-15)

What shipped: an opt-in RFC 3161 timestamp of each anchor's hash. It is off by default and sends nothing until the user turns it on and sets a service address (Settings, "External timestamp"). Code: `backend/core/external_timestamp.py`; the check is in `core/evidence_anchor.py` (`_review_timestamps`); the report lines are in `api/export.py` (`_chain_lines`); the settings are `GET/POST /api/config/external-timestamp`.

- **What leaves the machine.** A 59-byte TimeStampReq: version 1, the SHA-256 message imprint (the 32 bytes of `anchor_hash` itself, not a second hash of it), certReq TRUE. No policy OID, no nonce, no extensions. The disclosure shown in Settings: "When on, Vigil sends only a 32-byte hash of an anchor to the timestamp service you choose. No events, file paths or names leave this machine. This is a second outbound connection." The service also sees this machine's IP address.
- **Settings** (table `app_config`): `external_timestamp_enabled` (default off), `external_timestamp_url` (default empty), `external_timestamp_fallback_url` (optional; section 3 asks for a primary and a fallback; it is tried only if the first fails), `external_timestamp_ca_pem` (optional) and `external_timestamp_since_seq` (set when the switch is turned on).
- **Columns** (`evidence_anchors`, added by `_migrate` and also in schema.sql): `attempts`, `next_try_at`, `tsa_token` (DER), `tsa_name` (the URL that issued the token), `timestamped_at` (the token's genTime) and `error`, the names of section 4.2. `status` is `local_only` (never tried), `timestamped`, `pending` (the service was not reached; kept and retried, never dropped) or `failed` (the service answered but the reply was refused, malformed or for a different hash; still retried hourly).
- **Queue.** A scheduler job every minute, separate from the sealing and anchoring jobs, so a slow or unreachable service cannot delay them or an export. Backoff after a failure: 1 minute, 5 minutes, 30 minutes, then hourly; at most 5 anchors per run, oldest first; retries survive restarts because the queue is the table. Only anchors recorded since the switch was turned on (and the newest one existing at that moment) are stamped. Older anchors are not back-filled: each anchor carries the hash of the one before it, so a later token covers them.
- **Token check.** The token is parsed with a small DER reader (no new dependency; `asn1crypto` is not installed and section 9.3 allows a DER walk). The message imprint must equal the anchor's hash and genTime is read. The signature is checked only against a certificate the user supplies (`external_timestamp_ca_pem`): it must verify against a certificate carried in the token, that certificate must chain to the one supplied, have been valid at genTime and allow timestamping. With none supplied the token is `timestamp_unverified_signature`: the hash and time are read, the signature is not checked, and no wording calls it verified. The signature is checked for the newest timestamped anchor on each check; the imprint is checked for every held token.
- **Status.** Per anchor: `externally_timestamped` or `local_only`. Overall: `none` (no anchors), `local_only` (no valid token), `partially_timestamped` (some, but the newest anchor has no valid token, so events after the newest token are anchored locally only) or `externally_timestamped` (the newest anchor has a valid token). A token that does not match its anchor, or whose signature fails against the supplied certificate, is a mismatch (`timestamp_mismatch`, `valid` false) and does not count as a timestamp.
- **Report wording** (section 4.3 lines, extended): `Last anchor: <time> (seq N), status: timestamped by <url> at <genTime>`; `Anchors up to <time> carry a timestamp issued by <url>. Events recorded after the last timestamped anchor (<time>) are anchored locally only and are not yet externally protected.`; the signature line (`checked against the certificate you supplied`, or `timestamp_unverified_signature` with the reason); and, when anchors are waiting, `Waiting for timestamp: ... Events recorded after the last timestamped anchor are not yet externally protected.` With no anchors the report keeps `Anchoring: none.`; with local anchors and no token it keeps the Stage 1 `Anchoring: none` line.

Deviations from the task description and from sections 4 and 9, and why, in one place:

1. **Column names follow section 4.2** (`tsa_name`, `timestamped_at`, `status`, `error`), not `tsa_url`, `tsa_time` and `tsa_status`. `tsa_name` holds the URL.
2. **The imprint is the anchor hash itself**, as sections 2.1, 3 and 6.3 say, not a second SHA-256 of the hex string.
3. **A fallback address exists** because section 3 and the Stage 2 row of 9.1 ask for a primary and a fallback.
4. **Report lines follow the section 4.3 wording** where it differs from the task text ("not yet externally protected" instead of only "anchored locally"); the sentence "Anchors up to ... carry a timestamp issued by ..." is used as an added line.
5. **No nonce.** Section 9.3 describes a fixed structure; a nonce would be the only per-request random value in a request that otherwise holds only the digest. The cost is that a recorded reply could be replayed to this client, which is harmless here because the client accepts a token only if its imprint equals the anchor hash.

### Stage 2 limits

- **A token proves a hash existed by a time; it says nothing about the records.** It covers only what was in the anchor when it was made: the chain head, the count and the table digest. Events after the newest token are anchored locally only. The table digest is still recorded and not verified (section 2.3), so the alert, session, audit and coverage rows remain unprotected in this version.
- **The service is trusted for time only, and only as far as the user trusts the certificate they supplied.** Without a certificate nothing here authenticates the service, so a machine that can change the address or intercept the connection could make Vigil store a token it signed itself. That is why such tokens are labelled `timestamp_unverified_signature`.
- **The settings and the tokens are in the same database as everything else.** Someone who can write the database can delete a token and set the anchor back to `local_only`; the check cannot tell that from a token that was never obtained. What a held token does constrain is a rewrite that keeps its anchor: the anchor can no longer be changed without the imprint check failing. Holding the anchor hash somewhere else (the service, or a copy kept by the customer) is what shows a deleted token, and that needs the verifier of Stage 3.
- **The stamp time is the service's clock** and is the only time the report treats as proof of when (section 4.2). The anchor's own `created_at` is the local clock.
- **Not tested here:** a real timestamp service. Every test uses a fake service built from a throwaway key and certificate, and no request leaves the machine.
- **Frozen build:** the new module imports only `cryptography`, `httpx` and the standard library, all already in the executable, but a build was not made to confirm it (section 9.4, item 9).

## 14. Stage 3 as built (2026-10-15)

What shipped: a per-install signing key, a signed evidence bundle, and a standalone offline verifier. The bundle format and the exact hashing rules are written down in `evidence-bundle-spec.md` so a third party can reimplement the check. Code: `backend/core/signing_key.py`, `backend/core/evidence_bundle.py`, `GET /api/export/bundle?start=&end=` (the Export page has an "Export evidence bundle" card), and `verifier/vigil_verify.py`.

- **Signing key.** An Ed25519 key pair created on first use (when the first anchor is made, or the first bundle is exported) in the key directory (`VLAW_KEY_DIR`): `install.key` (the private key, wrapped with DPAPI in user scope on Windows, a plain file elsewhere or if DPAPI fails, the `protection` field says which) and `install.pub.json` (install id, public key, fingerprint = SHA-256 of the 32 public bytes). Only the public part is ever exported.
- **Anchor format v2.** New anchors carry `key_fingerprint`, so a timestamped anchor also pins the key. Anchors are checked by hashing their stored JSON as it is, so v1 anchors made before Stage 3 keep verifying. If the key cannot be created, a v1 anchor is recorded and anchoring is not blocked.
- **Bundle.** One zip: `events.jsonl` (the events of the range, every hashed column as text, with `row_hash` and `prev_hash`), `chain-proof.json` (the manifest: install id, public key and fingerprint, creation time, SHA-256 of every other file, the UTC date range, where the chain starts, the anchors that bind the range with any stored timestamp token inline, the limits), `chain-proof.sig` (Ed25519 over the manifest bytes), `coverage.json` (the report coverage block) and `gaps.json` (monitoring gaps overlapping the range). Exporting seals pending events and records an export anchor first. The rows run from the first event of the range through the last event of the first anchor that is at or after the range's last event, so that anchor's head can be recomputed. The anchors included run from the last anchor before the range through that end anchor. No settings, no private key, no webhook or certificate setting is included.
- **Verifier.** One file, standard library and `cryptography` only, no import from the backend, no network. Checks, each printed `PASS`, `FAIL` or `NOT CHECKED`: files (hashes, nothing unlisted), signature, key (fingerprint, and against the anchors), chain (re-hashed from the exported rows), anchors (hash, links, install), anchor-binds, timestamps. It prints the coverage block and the gaps. Exit code 0 nothing failed and nothing unchecked, 1 a check failed, 2 nothing failed but a check could not be made, 3 not a readable bundle. A timestamp token is `PASS` only with `--tsa-ca` and a checked signature; otherwise `NOT CHECKED: signature not authenticated`.

Deviations from the task description, and why (the doc was followed):

1. **File names follow section 5.3**: `chain-proof.json` and `chain-proof.sig` (the task called them `manifest.json` and `manifest.sig`), plus `events.jsonl`. Timestamp tokens are inline in the manifest's `anchors` list as in section 5.3, not separate files, so the signature covers them.
2. **Key storage follows section 5.1**: DPAPI-wrapped on Windows, with the plain-file fallback the doc names.
3. **Exit codes follow section 6.4**: 2 when nothing failed but a check could not be made. Exit 0 therefore means every check passed, which is stricter than "nothing failed".
4. **Result lines**: the failure result line of section 6.4 is replaced by `RESULT: FAILED`, because it names a cause the check cannot know, and a failed check shows a mismatch, not who or what caused it. `RESULT: CONSISTENT` and `RESULT: INCONCLUSIVE` are the doc's.
5. **`--trust-key`** (section 6.2) is supported; without it the verifier prints a note that nothing ties the key to an installation you expect, and does not count that as a failed check. `--earlier-anchor` is not implemented.
6. **No `report.pdf` or `report.json`** (section 5.3): Vigil does not store the PDF it generates, so there is none to include. The coverage block is `coverage.json`.
7. **The PDF "Evidence integrity" lines are unchanged** and do not mention the bundle.

### Stage 3 limits

- **The key is readable by the same Windows user.** DPAPI user scope gives no protection from a process of that user (section 5.2). A valid signature shows the bundle was not edited after export by anyone without the key; it does not show who exported it. Anyone with that access can also edit the data, sign a new bundle, and recompute the anchors; what then still constrains them is only a timestamp token whose signature you check against a certificate you hold, and a copy of an earlier anchor or bundle kept elsewhere.
- **Completeness is not shown.** Events that were never recorded (file reads, network, MCP calls, processes shorter than the polling interval) are not in the bundle, and nothing in it can show they happened.
- **Events after the last timestamp** are anchored on this machine only. The bundle's end is bound by an anchor, but only a checked token turns that into "not altered since <time>".
- **Alerts, sessions, audit entries and monitoring-gap records** are not integrity-protected in this version; `gaps.json` is included for reading, not as a protected record.
- **Not tested here:** a real timestamp service, a frozen build of the verifier (it is a source file; nothing was built), and the DPAPI path on a non-Windows machine.
