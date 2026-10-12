# Reachable-set inventory ("permission inventory"): design

Status: design only, no code written. Date: 2026-10-10.
Source read: branch pilot/p1-backend-safety at 15d23e6. No live database was read and no scan was run; everything below comes from code and schema.

The question this answers (from a security reviewer): **"Does Vigil see the reachable set, or only the reached one?"**

Today the honest answer is: only the reached one, and only part of it. Vigil records what agents did (file changes, process spawns, connections), not what the account they run under could have done. This document designs a Windows-first snapshot of the *reachable* set, recording **names, locations and metadata only, never secret values**, and a way to show it in the report without ever blurring "could reach" into "did access".

---

## 0. Summary of the recommendation

1. A daily (plus at-start and on-demand) scan, run in a separate short-lived worker process with hard time and path budgets, produces a versioned **snapshot** of items in about a dozen categories (secret-like environment variable names, SSH keys, cloud and tool config, git/npm/pip/docker credentials, Credential Manager target names, `.env` key names in watched repos, browser profile presence, mapped drives, token elevation and groups, WSL, Docker and ssh-agent reachability).
2. Values never enter the scanner's output: parsers read line by line, keep only the name side of `NAME=value`, and drop the rest immediately. A canary test proves a planted secret string never reaches the DB, logs, JSON or PDF.
3. Snapshots are stored in new tables with a per-source status (ok, denied, error, skipped) so "not scanned" is never confused with "nothing found". A diff between snapshots drives an optional low-severity "new credential appeared" alert.
4. The report gets a section **"Reachable by the agent's user account (names only)"** with a fixed sentence separating capability from behaviour, three redaction levels (counts, standard, full) and no default entry in the JSON export beyond what the chosen level allows.
5. Linking reached events to reachable items is allowed only for file-based items with an exact path match, and the report states what is not linked. Because Vigil does not record file reads (backend/api/export.py:163), "no linked activity" must never be presented as "not used".
6. Recommended MVP is about 7 working days (section 6). Integrity coverage uses the meta chain and anchors from docs/design/evidence-anchoring.md once those exist; until then the section says it is not tamper-evident.

---

## 1. What Vigil sees today (cited)

### 1.1 Environment variables (RL7)

- `RELEVANT_ENV_VARS` is a fixed set of four names: `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_API_KEY` (backend/watchers/process_watcher.py:98-104).
- The scan worker calls `proc.environ()` for the small set of agent PIDs and returns the **whole environment, values included**, to the parent over the subprocess boundary (backend/watchers/_process_scan_worker.py:92-119, the call is at :107). The parent keeps it in memory in `self._env_snapshot` (process_watcher.py:167, assigned at :658).
- `_scan_all_agent_processes_for_env_redirect` filters that to the four names (process_watcher.py:759-822, filter at :813) and `check_env_var_redirect` / `is_env_var_redirect` look only at the two URL-valued vars for a host change (backend/core/red_lines.py:356-374, :623). The two `*_API_KEY` vars are in the set but are not evaluated: "opaque credentials, not redirect targets" (red_lines.py:360).
- Consequences for this design: (a) the worker/parent pattern (subprocess with a timeout, killable, results as dicts) is the right template for an inventory scan; (b) **today full environment values already sit in the backend's memory**; the inventory must not add to that, so its env source must strip values inside the worker before anything is returned (section 2.1).

### 1.2 The credential counter

- `events` rows of type `cred_access` are written one per event, never aggregated, with severity `high` and the real path in `events.path` (backend/core/aggregator.py:857-884).
- A path counts as a credential path if its lowercase text contains any of `.env`, `.ssh`, `.aws`, `.pem`, `.key` (aggregator.py:52, :63-65; a duplicate list lives in backend/core/cross_agent.py:29-40). This is a substring test, so it is broad (for example any path containing `.key`).
- `sessions.cred_accesses` is computed at session close as a count of that session's `cred_access` events (backend/core/sessions.py:259, stored at :281-286) and used in the plain-English digest (backend/core/digest.py:28-30).
- So `cred_accesses` is a count of *observed file events on credential-looking paths*, a behaviour measure. It says nothing about which credentials exist.
- Limit that matters for the reviewer's question: Vigil's own report says "It does not record files being read" (export.py:163). A `cred_access` event is therefore a create/change/move/delete or a polling-fallback observation, not proof of reads, and the absence of one is not proof that nothing was read.

### 1.3 What is watched and how it is configured

- Default policy: `scope_directories: []`, `never_scope_directories: []`, `credential_paths: [".ssh", ".aws"]` (backend/main.py:119-137).
- `build_watch_paths` (main.py:140-202): scope directories as configured; credential entries that look like directories (`~`, trailing slash) become watched directories; if `credential_paths` is non-empty the project root `SESSION_LAUNCH_DIR` and every scope directory are also watched; `~/.ssh/`, `~/.claude/file-history/` and the project's `.claude`, `.cursor`, `.vscode` are always watched (main.py:186-192).
- `SESSION_LAUNCH_DIR` is simply `Path.cwd().resolve()` at import (backend/core/red_lines.py:191), with a per-agent override via `get_agent_workspace_dir` (red_lines.py:209-210). **For a backend started by the tray, the working directory is not necessarily a project.** The inventory must not treat `cwd` as "the repo"; it should scan `scope_directories` plus agent workspace directories actually observed.
- There is already a read-only audit of the user's Claude Code permission config (`audit_all_configs`, main.py:768-778, backend/core/config_auditor.py:45-132). That audits *configured deny rules*, which is related but different: it is "what the agent is told not to do", not "what it could reach". The inventory complements it; the report should not merge them.

### 1.4 Where a new section would appear

- The PDF is built in `export_pdf` (backend/api/export.py): Sessions at :561, Alerts at :594-596, Monitoring coverage at :600, "How to read this report" at :658. The JSON export returns `_build_summary` unchanged (summary assembled around :479, which also carries `report_notes`).
- `REPORT_NOTES` (export.py:157-165) is the single shared note list for PDF and JSON.
- The new section belongs after "Monitoring coverage" and before "How to read this report" (behaviour first, capability second), and as a new key in the summary for JSON.

---

## 2. Sources

For each source: what it tells a reviewer, how to detect it on Windows without reading secret values, cost, and false-positive risk. "Names" below always means identifiers (variable names, profile names, key file names), never contents.

General budget per source: 2 s wall clock, whole scan 10 s, all in the worker (section 3.3). All sources have a `status` of `ok`, `denied`, `error` or `skipped`.

### 2.1 Secret-like environment variable NAMES in the agent process

- **Tells the reviewer:** which credentials are injected straight into the agent's process (the easiest thing for an agent to use: no file access, no event).
- **Detect:** in the scan worker, `psutil.Process(pid).environ()` for the agent PIDs (same call as _process_scan_worker.py:107), then **keep only the names and discard the dict inside the worker**; return a list of names plus the classification, never values. Add a second, separate read of the per-user persistent environment names from the registry (`HKCU\Environment`, via `winreg`, `EnumValue` returns name and value; discard the value immediately). That second read answers "which variables would any new process of this user inherit?", which also matters when the agent was started before a variable was set.
- **Classification (name only):** case-insensitive match on tokens `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PWD`, `CREDENTIAL(S)`, `PRIVATE`, `AUTH`, `COOKIE`, `SESSION`, `CONNECTION_STRING`, plus an exact allowlist of well-known names (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOCKER_HOST`, `SSH_AUTH_SOCK`). Names containing path/lookup hints (`..._FILE`, `..._PATH`) are tagged "points to a file" without ever dereferencing it. A denylist of common non-secrets (`KEYBOARD...`, `MONKEY...`, `PUBLIC_KEY`, `SSH_AUTH_SOCK` as a socket pointer, `PATH`-like) prevents obvious noise.
- **Cost:** negligible (agent PIDs only, typically 0-5, already scanned today).
- **False positives:** moderate (`AUTHOR`, `KEYWORDS`, `SESSIONNAME` is a Windows built-in). Mitigated by the denylist and by showing the classification reason. A false positive costs a reviewer a glance; the harm is trust, so the report calls these "names that look like credentials".
- **Caveat to state:** the process environment is what the process started with. It does not show later `setx` changes (hence the registry read).

### 2.2 `~/.ssh`: keys and config hosts

- **Tells the reviewer:** whether private keys exist, their type, and whether a stolen file is usable without a passphrase; which hosts the account is configured to reach.
- **Detect:** enumerate `%USERPROFILE%\.ssh` (directory listing: names, sizes, mtimes). For each file that is not `*.pub`, `known_hosts*`, `config`, `authorized_keys`:
  - Key type: prefer the matching `.pub` file's first token (public data, safe). Otherwise read **at most the first 256 bytes**: the PEM header line says `RSA/EC/DSA PRIVATE KEY`, `OPENSSH PRIVATE KEY` or `ENCRYPTED PRIVATE KEY`.
  - Passphrase protection from the header only: `ENCRYPTED PRIVATE KEY` (PKCS#8) or a `Proc-Type: 4,ENCRYPTED` line (legacy PEM) means protected. For `OPENSSH PRIVATE KEY`, decode just the first ~100 base64 characters: the format starts with the magic `openssh-key-v1\0` followed by the cipher name; `none` means no passphrase. These bytes precede any key material, and the read is capped, so no key material is read.
  - `config`: parse `Host` lines (aliases) and `IdentityFile` paths line by line; **ignore `ProxyCommand`, `ProxyJump` arguments and `SetEnv` values** (can embed secrets). Hostnames are organisation-specific, so they are subject to masking (section 3).
  - `known_hosts`: count lines only (entries are usually hashed).
- **Cost:** a directory listing and a few tiny reads. **Gotcha:** `~/.ssh` is a Red Line directory Vigil itself watches (main.py:187), so Vigil's own scan could raise RL1 against itself; the scanner must run under a marker that the attribution layer ignores (the scan worker's PID is excluded), and this must be tested.
- **False positives:** low. A `.pub` file by itself is not a private key. Unknown file types are listed as "unclassified file in .ssh".

### 2.3 Cloud and tool configuration: `~/.aws`, `~/.azure`, GitHub CLI, gcloud, kube

All are "presence plus names", parsed line by line with values dropped.

| Item | Paths (Windows) | Names recorded | Also recorded (booleans only) |
|---|---|---|---|
| AWS | `%USERPROFILE%\.aws\credentials`, `config` | profile names (`[section]` headers) | per profile: static key lines present (`aws_access_key_id` key exists) vs role/SSO config |
| Azure | `%USERPROFILE%\.azure\` | file names; subscription display names from `azureProfile.json` only if present | `msal_token_cache.json` present (file name and mtime only, never opened) |
| GitHub CLI | `%APPDATA%\GitHub CLI\hosts.yml` | host names | an `oauth_token:` key exists in the file (newer versions keep the token in the OS keyring and the file only has the user) |
| gcloud | `%APPDATA%\gcloud\` | configuration names, account names from `configurations\config_*` | `credentials.db`, `application_default_credentials.json` present |
| kube | `%USERPROFILE%\.kube\config` | context, cluster and user entry names | per user entry: has `token`, `client-key-data` or `exec` key (key present only) |

- **Tells the reviewer:** which clouds and clusters the agent's account is already logged into, and whether there are long-lived static keys (higher risk) versus short-lived sessions.
- **Cost:** a handful of small files. **False positives:** low; a stale or empty profile file is reported as "present, 0 profiles".
- **Never done:** calling any cloud API to check whether a credential is valid, expired or what it may do. That would be a network call with the credential and is out of scope (section 6).

### 2.4 Git credential helper and stored credentials

- **Tells the reviewer:** whether git can push without a prompt, and whether credentials sit in plaintext.
- **Detect:** parse `%USERPROFILE%\.gitconfig` and `%XDG_CONFIG_HOME%\git\config` text for `[credential]` sections and the `helper =` value (names such as `manager`, `store`, `cache`; do not run `git` as a subprocess, to avoid its side effects and cost). `%USERPROFILE%\.git-credentials` present means the plaintext `store` helper is in use: record the **host** of each line (`https://user:pass@host` is split and everything except the host is discarded in memory) and the line count. Git Credential Manager keeps secrets in Windows Credential Manager (2.6); targets begin `git:https://...`.
- **Cost:** negligible. **False positives:** low. The plaintext file is a high-risk finding on its own.

### 2.5 npm, pip and Docker configuration

- `%USERPROFILE%\.npmrc` (and project `.npmrc` in scanned repos): lines with `_authToken`, `_auth`, `:_password`. Record the **registry host** from the key (`//registry.npmjs.org/:_authToken=...` gives `registry.npmjs.org`) and that a token is configured; drop the value.
- pip: `%APPDATA%\pip\pip.ini`, `%USERPROFILE%\.pypirc`. Record that an index URL **contains embedded credentials** (the `user:pass@` pattern) as a boolean plus the host; never store the URL. `.pypirc`: section names only.
- Docker: `%USERPROFILE%\.docker\config.json`. Record `credsStore` / `credHelpers` names and the registry keys under `auths` (these are host names); whether an `auths` entry carries an inline `auth` field is a boolean (the field is a base64 secret and is never kept).
- **Tells the reviewer:** which package registries and image registries the account can publish to (supply-chain reach).
- **Cost:** small files. **False positives:** low; an `auths` entry with no `auth` and a `credsStore` is reported as "uses credential helper", not as a stored token.

### 2.6 Windows Credential Manager target names

- **Tells the reviewer:** which services the account has saved logins for (git hosts, shared drives, RDP, apps), without seeing any password.
- **Detect:** run `cmdkey /list` (a documented tool that prints Target, Type and User only, never the secret) with a 5 s timeout inside the worker, and parse names. **Do not use `CredEnumerateW` through `ctypes`**: it returns `CREDENTIAL` structures whose blob pointers hold the secret, so values would be in Vigil's address space even if ignored. If `cmdkey` output proves too coarse, a later `CredEnumerateW` path would be the only place this design would let a secret transit memory, and it is therefore explicitly not part of the MVP.
- **Cost:** roughly 100 to 300 ms, one subprocess. **False positives:** low; many entries are Windows/Office/Microsoft account plumbing (`MicrosoftAccount:`, `WindowsLive:`, `virtualapp/didlogical`), so a built-in ignore list groups those under "system entries".
- **Sensitivity:** target names often embed host names and user names; they are masked at the `standard` level (section 3).

### 2.7 `.env` and key files in watched repositories

- **Tells the reviewer:** which projects hold local secrets and what they are called (`DATABASE_URL`, `STRIPE_SECRET_KEY`), so an access alert can be put in context.
- **Roots:** `scope_directories` from policy plus the workspace directories Vigil has actually observed for agents (red_lines.py:209-210). Not the process working directory (section 1.3).
- **Detect:** a bounded walk (section 3.3) matching names `.env`, `.env.*` (listing `.env.example`, `.env.sample`, `.env.template` separately as templates), `*.pem`, `*.key`, `*.pfx`, `*.p12`, `id_rsa*`, `id_ed25519*`, `credentials*.json`, `*.tfvars`. For `.env`-style files, read line by line, take the text before the first `=`, strip a leading `export`, **keep only that name (cap 500 names per file), and discard the line**. For key files, record the file only (path, size bucket, mtime), reading nothing. The walk skips `node_modules`, `.git`, `.venv`, `venv`, `dist`, `build`, `target`, `__pycache__`.
- **Cost:** the largest of any source; strictly bounded (20,000 directory entries and 3 s per root). **False positives:** moderate (test fixtures, example files). Templates are kept distinct, and names are classified (2.1) so a `.env` with `DEBUG`, `PORT` lines is shown as "5 names, 0 secret-like".
- **Windows detail:** OneDrive "files on demand" placeholders must not be opened (opening hydrates them and downloads the file). Skip content parsing for entries with the recall attributes (`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`, `FILE_ATTRIBUTE_RECALL_ON_OPEN`) and report them as "cloud placeholder, not parsed". Skip reparse points (junctions, symlinks) to avoid loops and surprise network reads.

### 2.8 Browser profile cookie and login stores (presence only)

- **Tells the reviewer:** that the account has logged-in browser sessions an agent could try to read (Chrome/Edge `Network\Cookies`, `Login Data`; Firefox `cookies.sqlite`, `logins.json`).
- **Detect:** directory listing of `%LOCALAPPDATA%\Google\Chrome\User Data\*`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\*` and `%APPDATA%\Mozilla\Firefox\Profiles\*`: profile directory names, whether the store files exist, size bucket, mtime. **Never open these files** (they are locked while the browser runs anyway, and opening them looks exactly like an infostealer).
- **What not to claim:** that the cookies are decryptable. Modern Chromium versions encrypt cookies with keys bound to the browser or the account, and what another process can decrypt differs by version and context; Vigil only reports presence.
- **Cost:** trivial. **False positives:** none for presence; high for implied risk, so the report wording stays at "present".

### 2.9 Mapped network drives and shares

- **Tells the reviewer:** which file servers the account has live mappings to (data an agent can reach without any credential prompt).
- **Detect:** `GetLogicalDrives` plus `GetDriveTypeW == DRIVE_REMOTE`, and `WNetGetConnectionW` for the UNC target (via `ctypes`, no subprocess). Run in the worker with a timeout: an unreachable server can make Win32 network calls block for tens of seconds, and this must never reach the event loop.
- **Cost:** low, with that timeout risk. **False positives:** disconnected-but-remembered drives are reported as "mapped (connection state unknown)". Never list the share's contents.

### 2.10 Token elevation and group memberships

- **Tells the reviewer:** whether the agent process is running with administrator rights, and which privileged groups its identity belongs to (including `docker-users`, `Administrators`, `Backup Operators`, `Hyper-V Administrators`).
- **Detect:** open the agent process with `PROCESS_QUERY_LIMITED_INFORMATION`, `OpenProcessToken`, then `GetTokenInformation` for `TokenElevation`, `TokenElevationType`, `TokenIntegrityLevel` and `TokenGroups`; resolve SIDs to names with `LookupAccountSid`. All through `ctypes` (no new dependency, and `psutil` does not expose this).
- **Subtleties to report precisely:** under UAC split tokens an administrator's non-elevated process carries the `Administrators` SID as **deny-only**; that is "member, not elevated" (could request elevation, which normally needs a consent prompt), not "is administrator". Distinguish `member, deny-only` from `elevated`.
- **If the open is denied:** the agent may be running at a higher integrity level or as another user than Vigil. That is itself a finding ("agent token could not be read; it may be running with more rights than Vigil") and is recorded as `denied`, not as "no privileges".
- **Cost:** tiny. **False positives:** low if the deny-only distinction is respected.

### 2.11 WSL, Docker and ssh-agent reachability

- **WSL:** list distribution names from the registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\*\DistributionName`); do **not** touch `\\wsl$\...` (merely accessing that path can start the distribution). Tells the reviewer a Linux userland with its own home directory (and its own `~/.ssh`, `~/.aws`) exists and is not covered by the Windows file sources above. The inventory records it as "not scanned inside", because looking inside would mean running code in the distribution.
- **Docker:** presence of the named pipe `\\.\pipe\docker_engine` (a directory listing of `\\.\pipe\`; never connect to it) together with `docker-users` membership from 2.10 means the account can start containers with host bind mounts, which is host-wide file reach. Also record the `DOCKER_HOST` variable *name* if set (value dropped).
- **ssh-agent:** presence of `\\.\pipe\openssh-ssh-agent` means a running Windows OpenSSH agent, so keys loaded in it can be used without any key file being read. Presence only: listing identities means connecting to the agent, which is an access and can trigger confirmation prompts.
- **Cost:** trivial. **False positives:** a stopped Docker Desktop has no pipe; the report says "not running at scan time".

---

## 3. Privacy rules, data model, schedule

### 3.1 Hard privacy rules

These are requirements, each with a test (section 6.4).

1. **No secret value is ever stored, logged, exported, returned by an API, or passed across the worker boundary.** Parsers are written as `for line in f:` loops that extract a name and drop the line; no function holds a whole file's text for secret-bearing formats (`.env`, `credentials`, `.npmrc`, `.git-credentials`, `.pypirc`, `config.json`, `hosts.yml`). The env source drops values inside the worker (this is a deliberate difference from the RL7 path in 1.1).
2. **Content reads are capped and minimal:** SSH key headers at most 256 bytes; `.env` etc. by line with an overall 1 MiB cap per file; key files (`*.pem`, `*.key`, `*.pfx`) and browser stores are never opened.
3. **Names are classified, not interpreted.** `classify_name()` returns `secret_like`, `credential_store`, `config` or `other` from the rules in 2.1. Classification never looks at a value.
4. **Errors never echo content.** Log lines and the `error` column hold the exception class and path only, never the offending line.
5. **Failure to parse a line drops the line**, it never logs it.

### 3.2 Redaction levels for the exported report

Chosen at export time, default `standard`, recorded in the report so a reader knows what they are looking at:

| Level | Shows | Masks |
|---|---|---|
| `counts` | per category: number of items, number secret-like, number of snapshot changes | all names and paths |
| `standard` (default) | category, tool, profile/context/env-var/key-file names, key types, passphrase yes/no, booleans such as "static key present" | organisation-specific identifiers: host names, Credential Manager targets, UNC paths, user names and repository paths are replaced by stable pseudonyms within the report (`host-1`, `share-2`, `repo-3`) and home paths by `%USERPROFILE%` |
| `full` | everything collected, still with no values | nothing beyond the no-values rule |

Rationale: a report is often handed to a reviewer or customer who should learn the *shape* of the exposure (three clouds, two unencrypted keys) without learning internal infrastructure names.

### 3.3 Storage, retention, access

- **Sensitivity.** The inventory is a tidy list of what is worth attacking. It sits in the same SQLite file the agent's user can already read (the DB path is under the user profile), so storage cannot hide it from the monitored account. The honest statement is: **the inventory adds little an agent could not enumerate itself in seconds** (it is, by definition, what the account can reach), but the aggregation, classification and "unencrypted key" flags are convenience, so it is kept minimal and not exposed casually.
- **Where:** new tables in the existing database (below). No separate file, no extra copy.
- **Retention:** keep the last 30 snapshots and nothing older than 90 days, whichever is fewer, but never delete the most recent complete snapshot; deletion runs after each scan.
- **Who can read or export:** not served by default API routes that other pages call. A dedicated route (`/inventory`, `/export/*` with an explicit `include_inventory=1` and a `redaction` level), gated by the same localhost/origin protection as the other export routes (see backend/tests/test_origin_guard.py). The PDF and JSON exports **do not include the section unless asked**, and say in the report notes when it was left out.
- **Never** copied into alert text, webhook payloads or the dashboard digest.

### 3.4 Data model (versioned snapshots plus diff)

```
inventory_snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT UNIQUE NOT NULL,         -- uuid4
  schema_version INTEGER NOT NULL,      -- version of the item format
  scanner_version TEXT NOT NULL,        -- Vigil version that scanned
  trigger TEXT NOT NULL,                -- startup | daily | manual
  started_at TIMESTAMP NOT NULL,
  finished_at TIMESTAMP,
  duration_ms INTEGER,
  status TEXT NOT NULL,                 -- complete | partial | failed
  scan_context TEXT,                    -- JSON: Vigil account SID, integrity, elevated, hostname
  agent_context TEXT,                   -- JSON: agent process token facts if readable, else null
  context_mismatch INTEGER DEFAULT 0,   -- 1 if agent runs as a different account than the scanned profile
  items_digest TEXT                     -- sha256 over canonical stable item rows (see section 5)
)

inventory_source_runs(
  snapshot_id INTEGER REFERENCES inventory_snapshots(id),
  source TEXT NOT NULL,                 -- env | ssh | cloud | git | pkgcfg | credman | dotenv | browser | drives | token | wsl_docker
  status TEXT NOT NULL,                 -- ok | denied | error | skipped | timeout
  item_count INTEGER DEFAULT 0,
  duration_ms INTEGER,
  error_class TEXT,                     -- exception class only, never content
  PRIMARY KEY (snapshot_id, source)
)

inventory_items(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id INTEGER REFERENCES inventory_snapshots(id),
  source TEXT NOT NULL,
  item_key TEXT NOT NULL,               -- stable identity: first 16 hex of sha256(source|normalised location|name)
  category TEXT NOT NULL,               -- ssh_key | cloud_profile | env_var | dotenv_file | credman_target | ...
  display_name TEXT,                    -- name only (env var, profile, key file, target)
  location TEXT,                        -- path or registry/pipe label, may be NULL
  classification TEXT NOT NULL,         -- secret_like | credential_store | config | capability | other
  risk_hint TEXT DEFAULT 'info',        -- info | review | elevated (see 4.2)
  attrs TEXT,                           -- JSON: types, booleans (passphrase_protected, static_key_present), counts; never values
  attrs_digest TEXT NOT NULL            -- sha256 of the STABLE attrs only (excludes mtime, size)
)
CREATE INDEX idx_inv_items_snapshot ON inventory_items(snapshot_id);
CREATE INDEX idx_inv_items_key ON inventory_items(item_key);
```

**Diff.** Computed on read (or cached in a small `inventory_changes(snapshot_id, prev_snapshot_id, change, item_key, summary)` table) by joining `item_key` between the latest two *complete* snapshots:
- `added`: key only in the newer one (a new credential appeared).
- `removed`: key only in the older one.
- `changed`: same key, different `attrs_digest` (for example an SSH key that became passphrase-less, a profile that gained a static key). Volatile attributes (mtime, size bucket) are excluded from the digest so routine edits do not look like changes.
- A source that was `denied`/`error` in either snapshot is excluded from the diff for that source and reported as "not comparable", so a failed scan cannot masquerade as "everything was removed".
- The first-ever snapshot is a baseline: no `added` entries and no alerts.

**Optional alerting.** An informational alert (`reason = 'inventory_new_credential'`, severity `low`, dedup by `item_key`, one per category per scan) for `added` items classified `secret_like` or `credential_store`. Severity `medium` only for: a private key without passphrase, `~/.git-credentials` present, a new static cloud key, an inline-credential index URL. Alerts carry the category and name per the redaction rules, never a value, and are not red-line (they are dismissible).

### 3.5 Schedule, budget, failure behaviour

- **When:** 60 s after backend start (after the first process poll at +5 s, see backend/main.py:394-399, so startup is not crowded), every 24 h, and on manual request. Not on every file event.
- **Where:** a short-lived worker process, following the existing pattern (separate process, killable, results as dicts; process_watcher.py:50-66 explains why environ/cmdline work was moved there, and main.py:31-39 shows the frozen-build sentinel dispatch `--process-scan-worker` / `--open-handle-worker`; a new `--inventory-worker` sentinel would join them). The backend event loop only awaits the result with `asyncio.timeout`. Worker runs at below-normal priority.
- **Budgets:** per source 2 s (credman 5 s), whole scan 10 s hard kill. Directory walks (`.env` and key files): at most 10 roots, depth 4, 20,000 entries and 3 s per root, no network roots, no reparse points, no cloud placeholders opened. **No full-disk scan, ever.** At most 5,000 items per snapshot (extra are counted, not stored, with a "truncated" flag).
- **Failure and denial:** each source is wrapped independently. `PermissionError`/`AccessDenied` gives `denied`; other exceptions `error` with the class only; timeout gives `timeout`. The snapshot becomes `partial` and lists which sources failed. A scan never raises into the scheduler, never retries within the same run, and the next scheduled scan tries again. If a source fails three scans in a row, the report says "inventory source X unavailable", so a reviewer is not left assuming it is empty.
- **Context check:** the file-based sources scan the profile of the account Vigil runs as. If the agent process's token (2.10) belongs to a different account, record `context_mismatch = 1` and **do not present file results as that agent's reach**. This matters later if the backend moves to a service account (docs/design/evidence-anchoring.md section 5.4): a service account's profile is not the monitored user's profile, so the scan would have to resolve the agent token's profile directory (via `ProfileList` in the registry) instead of `%USERPROFILE%`, or run its file sources in the user's session.

---

## 4. Report presentation

### 4.1 The section

Placed after "Monitoring coverage" (export.py:600) and before "How to read this report" (export.py:658). Heading and text:

> **Reachable by the agent's user account (names only)**
>
> This section lists what the account the agent runs under *could reach* on this computer, found by a scan at `<local time>` (`<complete | partial: N sources not scanned>`). It records names and locations only; no passwords, keys or tokens were read or stored. Being listed here does not mean any agent used an item. What agents actually did is shown under Sessions and Alerts.
>
> Vigil does not record files being read, so an item with no activity listed beside it has not been shown to be unused.

Rules for the wording:
- The verbs are **"could reach"**, **"is present"**, **"is configured"**. The words **"accessed"**, **"used"** and **"exposed"** never appear as statements about an item. (The sentence above uses "used" only in the negative to state what the list does not mean; the test in 6.4 checks the section text for the forbidden positive statements.)
- Content per category, standard level, one short block each, for example:
  - `SSH keys: 3 private keys. 1 has no passphrase. Types: ed25519, rsa.`
  - `Cloud: AWS 2 profiles (1 with a static access key), Azure 1 subscription, kube 3 contexts.`
  - `Environment of the agent process: 4 names look like credentials: AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, ...`
  - `Saved logins (Credential Manager): 12 entries (9 system, 3 other).`
  - `Repositories: 2 .env files with 14 names (6 look like credentials).`
  - `Privileges: agent process is not elevated; account is a member of Administrators (deny-only, can request elevation) and docker-users; Docker engine pipe present.`
- A "Changes since the previous scan" list (added/removed/changed) of at most ten lines, then "N more".
- Sources that did not run are listed explicitly: `Not scanned: Credential Manager (denied)`.
- If the integrity coverage of section 5 is not yet in place, the section ends with: `This inventory is not covered by the evidence chain.`

### 4.2 `risk_hint`

A fixed, documented mapping so the report does not editorialise: `elevated` for unencrypted private key, plaintext credential store, static cloud key, inline registry credentials, elevated or `docker-users` token; `review` for any other secret-like item; `info` otherwise. This only orders the list; it is not a score and not an alert level.

### 4.3 Linking reached events to reachable items (optional, evidence-bounded)

A reachable item and an observed event are linked **only** when both are true:
1. The item is file-based (SSH key file, `.aws\credentials`, `.npmrc`, a `.env` file, `.git-credentials`, `.docker\config.json`, kube config, and so on), and
2. An event in the report period has a normalised path equal to the item's path, or lying under an item that is a directory (for example `.ssh\`). The events considered are `cred_access` rows (path in `events.path`, aggregator.py:857-884) and the expanded `detail.paths` of file events (the helper in backend/core/cross_agent.py:43-83 already unpacks both).

Display: beside the item, `Activity in this period: 2 events (first 10:42), see Alerts`, with the count and the event time range, nothing else.

**Not linked, and the report says so** ("The following cannot be linked to activity because Vigil does not observe them"):
- Environment variables (reading one's own environment is not a file event).
- Credential Manager entries (API calls, not file events).
- Use of the ssh-agent or Docker pipe, browser store reads, network share reads (reads are not recorded at all; share activity is aggregated per directory).
- Anything a process did through an already-open handle.
- Any item for which no event exists: that means *no recorded change*, not "never touched".

A linked event is a fact about a path. It does not say which process read the credential, and the link must not be worded as "the agent used this credential".

---

## 5. Integrity

Per docs/design/evidence-anchoring.md (which exists), the inventory can join the integrity umbrella with little extra work:

- When a snapshot completes, append one **meta event** to the `meta_chain` described there (section 2.2): `kind = 'inventory_snapshot'`, `ref_id = scan_id`, `digest = items_digest`.
- `items_digest` is SHA-256 over the canonical sorted list of `(item_key, attrs_digest)` pairs, **salted with the install's `install_id`** from the anchoring design (section 2.1). Reason: the digest ends up in an anchor, which is the one thing allowed to leave the machine, and an unsalted digest of a low-entropy list of well-known names could be guessed. With the salt, only a hash of a salted digest leaves, and nothing about the contents can be derived.
- `inventory_snapshots` and `inventory_items` are added to the anchor's `tables_digest` set (anchoring doc section 2.3), so an anchored export proves the inventory section shown is the one that existed at export time.
- Effect: after anchoring, an edit to a past snapshot (for example deleting a new credential from the record) is detectable; before anchoring (stage 1 of that plan) the inventory is a plain mutable table and the report says so (4.1).
- What integrity does not give: it does not prove the scan was complete or the scanner honest. The `partial`/`denied` markers are the completeness statement, and they are themselves inside the digest.
- Do not block on this: the inventory ships first with its own `items_digest` column, unused until the meta chain exists.

---

## 6. MVP, scope, risks, tests

### 6.1 Recommended MVP (about 7 working days)

| Part | Content | Days |
|---|---|---|
| A | Tables, scan orchestration in a worker with per-source status, budgets, retention, schedule (start, daily, manual), `--inventory-worker` sentinel | 2 |
| B | Sources: env var names (+ registry names), SSH, AWS/Azure/gh/gcloud/kube, git credentials, npm/pip/docker config, `.env` and key files in scope dirs, with the name-classification rules | 3 |
| C | Diff, redaction levels, report section (PDF and JSON, opt-in), wording, "not scanned" lines, optional low-severity alert | 2 |

This answers the reviewer's question for the credential sources that matter most, on a defensible basis, and keeps the claim to "names only, could reach".

### 6.2 Phase 2 (not MVP)

- Token elevation and groups, Credential Manager targets, mapped drives, WSL/Docker/ssh-agent reachability (about 2 days; the token work needs the most care).
- Browser profile presence, tuning of classification (about 1 day).
- Linking reached events to items, 4.3 (about 2 days).
- Evidence-chain and anchor integration, section 5 (about 1 day once the meta chain exists).

### 6.3 Explicitly out of scope

- Reading, validating, decrypting or testing any credential value; calling any cloud or network API with a credential; judging what a credential is *allowed* to do (IAM/permission analysis).
- Scanning other users' profiles, the whole disk, the registry for secrets, process memory, password-manager vaults, browser cookie contents, or the inside of WSL distributions and containers.
- Blocking, remediating or rotating anything. This is inventory and reporting only.
- Network discovery (no port scans, no share enumeration beyond the account's own mappings).
- Real-time change detection (the file watcher already sees writes; a changed credential file could later mark the next scan as due, but that is not in this design).

### 6.4 Risks

- **Looks like malware.** A process that walks `.ssh`, browser profiles and Credential Manager resembles an infostealer, and EDR may flag Vigil. Mitigations: metadata-only behaviour, no opening of cookie stores or key files, signed binaries, a customer-facing description of exactly what is scanned, a documented allowlist note, and a switch to disable individual sources.
- **Scanning itself fires Vigil's own alerts** (RL1 on `~/.ssh`, cred_access on `.env` reads). Needs an explicit exclusion of the worker's PID and a test.
- **Scary or misleading output.** A long list can read as "the agent has everything". The wording rules (4.1), the `risk_hint` ordering and the per-category blocks are the control; the legal/marketing text should say "inventory of exposure", not "compromise".
- **Wrong profile.** Service-account deployment or an agent running as a different user makes the file results describe the wrong account (`context_mismatch`, section 3.5).
- **Stale daily snapshot.** The report states the scan time; a credential added an hour later is not in it.
- **Name classification** will have false positives and misses; showing the classification reason and keeping the list in one table keeps it reviewable.
- **Performance** on large repo trees or slow shares: bounded by the budgets and the worker kill, but needs measuring on a real machine before shipping the walk defaults.
- **Sensitive data in a world-readable store**: see 3.3; the mitigation is minimising what is stored, not secrecy.

### 6.5 Test plan (fake files and fake env vars only)

All scanners take an injected "roots" object (home, appdata, localappdata, environment dict, command runner, registry reader) so tests never touch the real profile, registry or `cmdkey`. Tests use a fresh `VLAW_DATA_DIR` and temp directories.

1. **Canary / no-values test (the most important one).** Build a fake profile in a temp dir whose files contain the sentinel `SENTINEL_SECRET_DO_NOT_LEAK_91c7` as the *value* in every secret-bearing format: `.env` lines, `.aws\credentials` keys, `.npmrc` `_authToken`, `.git-credentials` password, `.pypirc` password, `.docker\config.json` `auth`, kube `token`, a pip index URL `https://u:SENTINEL...@host/simple`, and an environment dict with `AWS_SECRET_ACCESS_KEY=SENTINEL...`. Run a full scan and exports at all three redaction levels, then assert the sentinel appears **nowhere**: not in any table (dump the whole DB), not in captured logs (`caplog`), not in the JSON export, not in the PDF text (patch `Canvas.drawString`, as the existing export tests do), not in the worker's returned payload.
2. **Parsers:** golden tests per source with fake files: AWS profile names and the `static_key_present` boolean; SSH header classification using synthetic files (an `OPENSSH PRIVATE KEY` whose decoded prefix says cipher `none` versus `aes256-ctr`, a PKCS#8 `ENCRYPTED PRIVATE KEY`, a legacy PEM with `Proc-Type: 4,ENCRYPTED`; none contain real key material, only headers plus filler text); `.env` parsing handles `export`, quotes, comments, blank lines and `=` inside values, and keeps names only; the 256-byte SSH read cap (a file with a long filler body proves no read beyond it, using a wrapper that records read sizes).
3. **Classification:** table-driven name tests including the false-positive denylist (`KEYBOARD_LAYOUT`, `AUTHOR`, `PUBLIC_KEY`) and well-known names.
4. **Bounds:** a tree 8 levels deep with 30,000 files: scan stops at depth 4 and at the entry cap, reports `truncated`, and finishes within the budget; reparse points and `node_modules` are skipped; cloud-placeholder entries (simulated attribute flags) are listed but not opened (the test fails if `open` is called on them).
5. **Failure behaviour:** simulate `PermissionError` per source, a timeout (a runner that sleeps past the budget), and an exception: the snapshot is `partial`, `inventory_source_runs` shows `denied`/`timeout`/`error`, nothing is raised to the scheduler, and a following scan can still succeed. A "denied" source in one snapshot is excluded from the diff, not shown as removals.
6. **Diff:** two fake snapshots: added key, removed key, changed passphrase flag, unchanged mtime-only change (must not appear), first snapshot gives no alert, an `added` secret-like item gives exactly one low alert and a private-key-without-passphrase gives a medium one, and dedup holds across repeated scans.
7. **Redaction:** `counts` contains no names or paths; `standard` replaces host names, targets, UNC paths and repo paths with stable pseudonyms (same host maps to the same `host-N` within a report, different hosts differ) and `%USERPROFILE%`; `full` shows names. Default is `standard`; the chosen level is printed in the report.
8. **Report wording:** the section has the exact heading and the two fixed sentences from 4.1; the section text never asserts `accessed`/`used`/`exposed` about an item (regex over the section's drawn lines); the "not scanned" lines appear when a source is denied; the section is absent unless requested and the note says so.
9. **Linking:** a `cred_access` event on the fake `.aws\credentials` path links; an event under `.ssh\` links to the directory item; an environment-variable item never links; an item with no event shows no activity text but still carries the "has not been shown to be unused" sentence.
10. **Own-alert suppression:** with the file watcher test harness, the scan worker reading the fake `.ssh` directory raises no RL1 alert and no `cred_access` event.
11. **Retention and limits:** more than 30 snapshots prunes the oldest but never the latest complete one; more than 5,000 items sets `truncated` and does not store the extras.
12. **Integration with anchoring (later):** the snapshot completion appends a meta event, and editing a stored item changes `items_digest` so the verifier flags it against an anchored head.

---

## 7. Open questions

1. Should `standard` masking be the default for the PDF, or should the default be `counts`, with names only on explicit request? (Recommendation above is `standard`.)
2. Which environment is the agent's: the process Vigil sees, or what a *new* agent session would inherit? The design records both (process environment plus `HKCU\Environment` names); the report must label them separately.
3. Is the `cmdkey` route acceptable, or does the customer want Credential Manager excluded entirely?
4. Should WSL contents be scanned in a later phase (running a command inside the distribution is a materially different action from reading Windows files)?
5. How do we describe the feature externally so it is not mistaken for a vulnerability scanner or for a credential harvester?
