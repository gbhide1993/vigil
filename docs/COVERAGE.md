# What Vigil monitors in this version

Verified against the code at version 0.9.0 (branch pilot/p1-backend-safety). This page states what is running, what each part can and cannot see, and what is planned. It makes no claim of completeness: anything not listed as seen should be treated as not seen.

The running state of the optional monitors is also reported live: `GET /health` returns `network_monitoring` and `mcp_monitoring` ("on" or "off", read from the scheduler), and every PDF/JSON report repeats them in its coverage section and adds a note while a monitor is off.

## 1. What is running

Registered at startup in `backend/main.py`.

| Component | State | Interval | Notes |
|---|---|---|---|
| File watcher (`watchers/file_watcher.py`) | Running | Event-driven | See section 2. Installs run the native folder observer (or polling). The ETW tier is experimental and off by default: it is used only when `VLAW_FILE_WATCHER=etw` is set, needs an elevated backend, and is not verified end to end; `GET /health` reports `etw_available` and `etw_unavailable_reason`. |
| Process watcher (`watchers/process_watcher.py`) | Running | Every 30 s, first run 5 s after start | Also drives the coverage heartbeat. |
| Aggregator flush | Running | Every 15 s | Writes buffered file events to the database. |
| File burst check | Running | Every 30 s | Correlates bursts of file changes with agent processes. |
| Evidence chain sealing | Running | Every 15 s | Hash-chains the events table only. |
| Evidence bundle export and `verifier/vigil_verify.py` | Available on request (Export page) | When you export | Signed zip of a day's events with chain rows, anchors and timestamp tokens, checked offline. Shows no edit after export without the key; not who exported it, not completeness, not events after the newest timestamp. |
| External timestamp queue | Running, does nothing unless you turn it on | Every minute | Opt-in. Off by default; with the switch off or no address set, nothing is sent. |
| Baseline update | Running | Hourly | Folds ended sessions into the per-agent baseline. |
| Credential detection | Running, no separate watcher | Event-driven | A change to a credential-looking path is classified from file events on paths containing `.env`, `.ssh`, `.aws`, `.pem` or `.key`, made by the file watcher. |
| Network watcher (`watchers/network_watcher.py`) | **Disabled** | n/a | Commented out at `main.py:411`. Disabled in commit e821731 (2026-09-29, watcher-starvation deadlock fix): its resolution phase does blocking I/O. Re-enable needs bounded work per tick, an off-switch and a loop-delay measurement (see the comment in `main.py`). |
| MCP watcher (`watchers/mcp_watcher.py`) | **Disabled** | n/a | Commented out at `main.py:430`. Disabled in commit e821731: it contended with the process watcher for the same PowerShell/WMI scans. |
| Idle session sweep (`SessionManager.close_idle_sessions`) | **Disabled** | n/a | Commented out at `main.py:445`. Disabled in commit e821731 pending an event-loop audit. |
| Startup session recovery | Runs once at start | n/a | Closes sessions left open by a previous run. |

Consequence of the disabled sweep: a session is closed (and scored by the volume, time-of-day, ratio and cross-agent checks) only when the same agent becomes active again after more than 5 minutes idle, or at the next backend start. Those alerts can therefore be late, and an open session has none yet.

## 2. What each running watcher captures, and its limits

### File watcher

- **Captures:** files created, changed, moved or deleted, with the time of the change and the agent it is attributed to. Credential-path changes are stored as individual events; other changes are aggregated per directory (the stored row lists up to 50 file paths per 15-second window).
- **Does not capture:** file reads. No tier reports them. On Windows the native observer only reports create, modify, move and delete, and the ETW tier deliberately ignores read events. Any report sentence about "reading" a file is therefore not backed by data.
- **Where it looks:** only the watched set: the project folders you add in Settings (stored in the database; the policy file is just a first-run seed), `~/.ssh`, and `~/.claude/file-history`, plus any directory-shaped `credential_paths` entry. The backend's own working directory is no longer watched (for the installed app that was Vigil's own install folder), and changes inside Vigil's install and data folders are never recorded. With no project folder added, nothing but `~/.ssh` and Claude's checkpoint cache is watched, and the report and Status page say so. A project in a folder that is not watched is not seen unless the ETW tier is running.
- **ETW tier:** experimental and off by default. It is used only when `VLAW_FILE_WATCHER=etw` is set; it needs the backend to run as Administrator and is not verified end to end. If it runs and `pyetwkit` loads, file changes are seen for known or suspected agent processes together with the process ID the trace reports. It records them only in the watched set (the project folders, the credential folders, the never-scope folders), for credential-looking paths (`.env`, `.ssh`, `.aws`, `.pem`, `.key`), in the agents' own folders (`~/.claude`, `~/.codex`) and in persistence locations (your Startup folder, PowerShell profiles, `.bashrc`-style shell profiles in your home folder, `~/.gitconfig`). Anything else is counted in memory and not recorded (the report and `GET /health` give the count), so an agent's app writing its own cache files cannot flood the database. ETW device paths (`\Device\HarddiskVolume3\...`) are converted to drive-letter paths before they are compared or stored; events stored by earlier versions may still show the device form. `GET /health` reports `file_watcher_tier` (`etw`, `native` or `polling`), `etw_available` and `etw_unavailable_reason` (for example "kernel tracing needs administrator"), and the tray tooltip shows the reason only when ETW was asked for and is not running. `VLAW_FILE_WATCHER` (`auto`, `etw`, `native`, `polling`) picks the tier: `auto` (the default) and `native` use the native observer, `polling` uses polling, and only `etw` tries ETW. If ETW was chosen and starts but 500 file events in a row have no file name, the backend switches to the native observer and `GET /health` says why in `etw_unavailable_reason` (`etw_requested` is true, `etw_available` false). Such events are counted as `no_file_name_not_recorded` in `file_events_not_recorded`. A trace session named `vlaw-kernel-file` left by a force-killed backend is stopped before ETW starts. Without ETW (the normal case), the process ID is a best guess (the known agent running, refined by which candidate has the file open), so attribution is lower confidence.
- **ETW limits (experimental tier):** the 500-event fallback limit (500 file events in a row with no file name) is an estimate, not a measured value. Events lost in the Rust-side channel (default capacity 10,000) before they reach Python are not counted anywhere. The FileObject-to-path cache is not invalidated on Close or Cleanup, so a reused FileObject can map to an earlier file's path.
- **Attribution:** Kernel file tracing is not running, so file changes are attributed to the agent running at the time. A change made by you may be shown under an agent. The native and polling observers learn that a file changed, not who changed it, so the event goes to whichever recognised agent process was running; if more than one agent was running, the one that has the file open is chosen when that can be determined; otherwise the change is not given to any of them but recorded under the name "unattributed" with confidence "low" and the label "<n> agents active, cannot tell which wrote this". Every such event is stored with a confidence that is never "high": "low" when it is recorded as unattributed, "medium" when one agent was running (or the file's owner was determined) but the writer was not verified. A file location in an agent's own folder (`~/.claude` for Claude Code, `~/.codex` for Codex) is used at medium confidence: such a change is given to that agent when it is running, and labelled "attributed to <agent> by file location, confidence medium". The location names whose folder it is, not the process that wrote the file, so it is not shown as exact. The UI feed and the reports label these "attributed to <agent> (best guess)". Events from the optional ETW tier are shown without the "best guess" wording; that tier is not verified end to end. If no agent process is running when a file changes, the change is not recorded at all (it is only used for burst correlation); so a change you make with no agent running leaves no event.
- **Ignored folders:** changes inside generated or dependency folders (`node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.next`, `target`, `.pytest_cache`, `.mypy_cache`, `.tox`, `coverage`, caches) and most of `.git` (objects, refs, logs, index) are dropped before any other work, in every watcher tier. They are counted, and the report says so: "N changes in generated or dependency folders (node_modules, build outputs) were not recorded." (shown only when N is above zero and the rule is on; the count is since the backend started). `.git/hooks`, `.git/config` (also inside `.git/modules/<name>/`), `.gitmodules`, `.env` files and any credential-looking path are never ignored, even inside these folders. `VLAW_IGNORE_GENERATED=0` switches the rule off.
- **Bounds:** at most 2,000 raw file events can be waiting for the event loop, at most 1,000 recorded events are buffered per 15-second write, and the ETW tier allows 1,000 in flight. Anything dropped because of these limits is counted and the report says "N file changes were not recorded because too many arrived at once." `GET /health` returns the same counts as `file_events_not_recorded` (`dropped_total`, `dropped_by_kind`, `outside_scope_not_recorded`, since when) and the per-session PDF prints them when they are not zero. The counts are for the whole backend run, not per session.
- **Delay:** real time with the native observer; buffered and written within about 15 seconds. The polling fallback can be 5 to 20 seconds late.

### Process watcher

- **Captures:** processes that started since the previous check and belong to a known agent, descend from one, or score as agent-like by behaviour. Stored: name, parent, command line with common secrets replaced by `[REDACTED]` on a best-effort basis, and a flag if the command is on the sensitive list.
- **Does not capture:** a process that starts and ends between two 30-second checks. Command lines of processes it could not read (access denied). Unusual secrets that the redaction patterns miss may still appear in stored command text.
- **Limits:** on a cold start up to 50 new processes per cycle get their command line fetched; the rest are recorded by name only. The scan runs in a separate process with an 18 second timeout, and a failed scan keeps the previous snapshot.
- **Environment:** for agent processes only, it keeps `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` (credentials and query stripped) and whether `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set. No other environment value is kept.

### Not watchers, but they affect what you see

- **Attribution** works from process names (Claude Code, Cursor, Copilot, Codex and a few others), parent chains and a behaviour score. An agent that is not recognized is only seen if it scores as agent-like.
- Session durations and counts can be off: sessions close lazily because the scheduled idle sweep is off.
- **Running, open (idle) and active:** an agent is *running* when one of its processes exists (a desktop app or an editor extension's background helper counts). It is *active* only after real activity in the last 5 minutes: a file change attributed to it, a network or MCP event, or a new tool or shell process started under one of its processes. A long-lived helper, a process that was already running when Vigil started, or an open session alone is not activity; such an agent is shown as "open, idle". The tray tooltip, the sidebar and `/api/agents` use the same rule. A process Vigil has already recorded (same pid and creation time) is not recorded again after a restart.
- **Evidence chain:** hashes the stored events and checks them for consistency, run by Vigil itself on its own database. It does not cover alerts, dismissals, policy, sessions or coverage data, and nothing outside this computer holds a copy.

## 3. Red-line rules

There are nine rules (RL1 to RL8, plus RL7b). They cannot be disabled. The README previously said "eight"; that count leaves out RL7b. Five can fire now. Four depend on a signal that this version does not produce.

| Rule | Fires on | Depends on | Available now |
|---|---|---|---|
| RL1 SSH directory | A file under a `.ssh` directory is created, changed, moved or deleted. The alert title is "SSH directory changed". Reading a key is not detected. | File events (watched path) | Yes |
| RL2 `.env` outside workspace | A `.env` file read outside the active project. The alert text says the rule requires file-read events, which are not recorded on Windows in this version. | A file-read event | **No.** Reads are never produced, so this cannot fire. |
| RL3 Claude cache write | A write to Claude's hidden file-history folder when the agent has no active or recent session | File events | Yes. A write during an active session raises no alert; the report shows an info line. |
| RL4 Unrecognised destination | A connection to a destination outside the approved list | Network watcher | **No.** Network watcher is off. |
| RL5 Sensitive command | A process whose command matches the sensitive list (`curl`, `wget`, `ssh`, `nc`, force push, recursive delete, encoded PowerShell, download-and-execute, and similar) | Process watcher | Yes, for processes caught by the 30-second check |
| RL6 Cross-project read | A read of files in a different project than the active one. The alert text says the rule requires file-read events, which are not recorded on Windows in this version. | A file-read event | **No.** Same reason as RL2. |
| RL7 Environment redirect | `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` set to an unrecognized host | Process environment, 30-second check | Yes |
| RL7b Config then execute | A project config file (`.claude`, `.cursor`, `.vscode`) written, then a spawn or write elsewhere within a short window | File events and process watcher | Yes, if the config path is in the watched set |
| RL8 MCP auto-approval | An `.mcp.json` write followed by a connection to an unapproved MCP server | MCP watcher | **No.** The rule is only evaluated from the MCP watcher, which is off. |

RL2 and RL6 stay in the code, but their alert text now says they require file-read events, which Vigil does not record on Windows in this version, so they cannot fire. RL1 detects creates, changes, moves and deletes under `.ssh`; its title says "changed" and the report text says reading is not detected. Rule checks run only on the events the watchers produce; none of them sees a read.

## 4. Other alerts

| Alert | State |
|---|---|
| Credential path change (policy; title "Credential path changed") | Active, on file changes to credential-looking paths in the watched set |
| Out-of-scope and never-scope directory changes (policy) | Active only if `scope_directories` / `never_scope_directories` are set; empty by default |
| Unapproved agent detected | Active |
| Suspicious command (policy) | Active; skipped when RL5 already fired for the same process |
| Unusual activity volume | Active at session close; needs floors and 5 history sessions (see `core/activity_filter.py`) |
| Time-of-day anomaly | Active at session close, only with a corroborating signal; otherwise an info line in the report |
| Unrecognised network destination (policy and RL4) | **Not produced** while network monitoring is off |
| Unapproved MCP server connection | **Not produced** while MCP monitoring is off |
| Checkpoint writes | No alert; one info line per session in the report |

## 5. Summary

| Sees | Does not see | Planned (not built) |
|---|---|---|
| File creates, changes, moves and deletes in the watched set | File reads | A source of file-read events, if one is found |
| Processes that are running at a 30-second check, with command text | Processes that start and end between checks | Moving to a shorter or event-based process source |
| Credential-looking file changes in the watched set | Credential access that is a read only | none |
| Agent environment redirect (two variables) | Any other environment value (deliberately not kept) | none |
| Which agent was active, for known or behaviourally agent-like processes | Unrecognized tools | none |
| When Vigil itself was running (coverage heartbeat and gaps) | Anything while it was not running | none |
| A consistency check of stored events, against local anchors; an external timestamp of anchor hashes only if you turn it on (a token covers only what existed when its anchor was made) | Alerts, dismissals, policy, sessions, coverage data in that check; events after the newest token | Signed export and a standalone verifier (`docs/design/evidence-anchoring.md`) |
| Nothing for network connections | All network connections and destinations | Network monitoring |
| Nothing for MCP connections | MCP server connections and tool calls | MCP connection monitoring |
| Nothing for reachable credentials | What the agent's account could reach but did not use | Permission inventory (`docs/design/reachable-set-inventory.md`) |

"Planned" means a design or a documented prerequisite exists. It is not a delivery date and none of it is active.

## 6. Network contact

What the shipped app (backend, tray and web interface) contacts over the network:

- **By default: nothing.** The web interface, its scripts, styles and fonts (Inter and JetBrains Mono, bundled and
  licensed in `frontend/THIRD_PARTY_LICENSES.md`) are served from the local backend. The tray and the interface
  only talk to `localhost:7422`. There is no update check, no telemetry upload and no license server call (the
  license is verified offline). Usage events are appended to a local file (`~/.vigil/usage.jsonl`) and never sent.
- **Only if you save a webhook URL in Settings:** the backend POSTs the daily summary text (summary sentence, clean-day
  and agent counts) to that URL, at 9:00 each day and when you press the test button. With no URL saved, nothing is
  sent. `VLAW_CORE_ONLY=1` disables this feature entirely.
- **Only if you turn on the external timestamp in Settings and set a service address (opt-in, off by default):** the
  backend POSTs an RFC 3161 request to that address (and to a fallback address if you set one) for each anchor
  that has no token. The request is 59 bytes: the 32-byte SHA-256 anchor hash, and no events, file paths, names or other
  data. This is a second outbound connection, after the webhook. A failed or offline attempt is retried (1 minute, 5
  minutes, 30 minutes, then hourly) and never delays monitoring, sealing, anchoring or an export. A token covers
  only what existed when that anchor was made; later events are anchored locally only until the next token.
  Without a certificate you supply in Settings, the token's signature is not checked and the token is marked
  `timestamp_unverified_signature`. Nothing is sent while the switch is off or the address is empty.
- A test (`backend/tests/test_no_external_loads.py`) fails if the interface source or the built interface loads
  any script, style, font or image from outside the machine.
