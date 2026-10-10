# What Vigil monitors in this version

Verified against the code at version 0.9.0 (branch pilot/p1-backend-safety). This page states what is running, what each part can and cannot see, and what is planned. It makes no claim of completeness: anything not listed as seen should be treated as not seen.

The running state of the optional monitors is also reported live: `GET /health` returns `network_monitoring` and `mcp_monitoring` ("on" or "off", read from the scheduler), and every PDF/JSON report repeats them in its coverage section and adds a note while a monitor is off.

## 1. What is running

Registered at startup in `backend/main.py`.

| Component | State | Interval | Notes |
|---|---|---|---|
| File watcher (`watchers/file_watcher.py`) | Running | Event-driven | See section 2. The ETW tier needs Administrator and fell back to the native observer on this machine's log. |
| Process watcher (`watchers/process_watcher.py`) | Running | Every 30 s, first run 5 s after start | Also drives the coverage heartbeat. |
| Aggregator flush | Running | Every 15 s | Writes buffered file events to the database. |
| File burst check | Running | Every 30 s | Correlates bursts of file changes with agent processes. |
| Evidence chain sealing | Running | Every 15 s | Hash-chains the events table only. |
| Baseline update | Running | Hourly | Folds ended sessions into the per-agent baseline. |
| Credential detection | Running, no separate watcher | Event-driven | Credential access is a classification of file events on paths containing `.env`, `.ssh`, `.aws`, `.pem` or `.key`, made by the file watcher. |
| Network watcher (`watchers/network_watcher.py`) | **Disabled** | n/a | Commented out at `main.py:411`. Disabled in commit e821731 (2026-09-29, watcher-starvation deadlock fix): its resolution phase does blocking I/O. Re-enable needs bounded work per tick, an off-switch and a loop-delay measurement (see the comment in `main.py`). |
| MCP watcher (`watchers/mcp_watcher.py`) | **Disabled** | n/a | Commented out at `main.py:430`. Disabled in commit e821731: it contended with the process watcher for the same PowerShell/WMI scans. |
| Idle session sweep (`SessionManager.close_idle_sessions`) | **Disabled** | n/a | Commented out at `main.py:445`. Disabled in commit e821731 pending an event-loop audit. |
| Startup session recovery | Runs once at start | n/a | Closes sessions left open by a previous run. |

Consequence of the disabled sweep: a session is closed (and scored by the volume, time-of-day, ratio and cross-agent checks) only when the same agent becomes active again after more than 5 minutes idle, or at the next backend start. Those alerts can therefore be late, and an open session has none yet.

## 2. What each running watcher captures, and its limits

### File watcher

- **Captures:** files created, changed, moved or deleted, with the time of the change and the agent it is attributed to. Credential-path changes are stored as individual events; other changes are aggregated per directory (the stored row lists up to 50 file paths per 15-second window).
- **Does not capture:** file reads. No tier reports them. On Windows the native observer only reports create, modify, move and delete, and the ETW tier deliberately ignores read events. Any report sentence about "reading" a file is therefore not backed by data.
- **Where it looks:** only the watched set. With the default policy (`scope_directories` empty) that is `~/.ssh`, `~/.claude/file-history`, the backend's launch directory (recursive, because `credential_paths` is set), and the project `.claude`, `.cursor` and `.vscode` folders under it, plus any `scope_directories` you configure. On this machine the log shows 7 watched paths. A project in another folder is not seen unless you add it to `scope_directories`, or unless the ETW tier is running.
- **ETW tier:** if the backend runs as Administrator and `pyetwkit` loads, file changes are seen for known or suspected agent processes with an exact process ID. Without it, the process ID is a best guess (the known agent running, refined by which candidate has the file open), so attribution is lower confidence.
- **Attribution:** a change is recorded against an agent only if a known or suspected agent is identified. Other changes are used for burst correlation but not stored as agent events.
- **Delay:** real time with the native observer; buffered and written within about 15 seconds. The polling fallback can be 5 to 20 seconds late.

### Process watcher

- **Captures:** processes that started since the previous check and belong to a known agent, descend from one, or score as agent-like by behaviour. Stored: name, parent, command line with common secrets replaced by `[REDACTED]` on a best-effort basis, and a flag if the command is on the sensitive list.
- **Does not capture:** a process that starts and ends between two 30-second checks. Command lines of processes it could not read (access denied). Unusual secrets that the redaction patterns miss may still appear in stored command text.
- **Limits:** on a cold start up to 50 new processes per cycle get their command line fetched; the rest are recorded by name only. The scan runs in a separate process with an 18 second timeout, and a failed scan keeps the previous snapshot.
- **Environment:** for agent processes only, it keeps `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL` (credentials and query stripped) and whether `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set. No other environment value is kept.

### Not watchers, but they affect what you see

- **Attribution** works from process names (Claude Code, Cursor, Copilot, Codex and a few others), parent chains and a behaviour score. An agent that is not recognized is only seen if it scores as agent-like.
- **Evidence chain:** hashes the stored events and checks them for consistency, run by Vigil itself on its own database. It does not cover alerts, dismissals, policy, sessions or coverage data, and nothing outside this computer holds a copy.

## 3. Red-line rules

There are nine rules (RL1 to RL8, plus RL7b). They cannot be disabled. The README previously said "eight"; that count leaves out RL7b. Five can fire now. Four depend on a signal that this version does not produce.

| Rule | Fires on | Depends on | Available now |
|---|---|---|---|
| RL1 SSH directory | A change to a file under a `.ssh` directory | File events (watched path) | Yes |
| RL2 `.env` outside workspace | A `.env` file read outside the active project | A file-read event | **No.** Reads are never produced, so this cannot fire. |
| RL3 Claude cache write | A write to Claude's hidden file-history folder when the agent has no active or recent session | File events | Yes. A write during an active session raises no alert; the report shows an info line. |
| RL4 Unrecognised destination | A connection to a destination outside the approved list | Network watcher | **No.** Network watcher is off. |
| RL5 Sensitive command | A process whose command matches the sensitive list (`curl`, `wget`, `ssh`, `nc`, force push, recursive delete, encoded PowerShell, download-and-execute, and similar) | Process watcher | Yes, for processes caught by the 30-second check |
| RL6 Cross-project read | A read of files in a different project than the active one | A file-read event | **No.** Same reason as RL2. |
| RL7 Environment redirect | `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` set to an unrecognized host | Process environment, 30-second check | Yes |
| RL7b Config then execute | A project config file (`.claude`, `.cursor`, `.vscode`) written, then a spawn or write elsewhere within a short window | File events and process watcher | Yes, if the config path is in the watched set |
| RL8 MCP auto-approval | An `.mcp.json` write followed by a connection to an unapproved MCP server | MCP watcher | **No.** The rule is only evaluated from the MCP watcher, which is off. |

Rules that read "read" in their alert text (RL2, RL6) describe file-read events that never arrive on this platform. Rule titles for RL1 use "accessed"; what is detected is a change.

## 4. Other alerts

| Alert | State |
|---|---|
| Credential access (policy) | Active, on file changes to credential-looking paths in the watched set |
| Out-of-scope and never-scope directory access (policy) | Active only if `scope_directories` / `never_scope_directories` are set; empty by default |
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
| A consistency check of stored events | Alerts, dismissals, policy, sessions, coverage data in that check | Anchoring and signed export (`docs/design/evidence-anchoring.md`) |
| Nothing for network connections | All network connections and destinations | Network monitoring |
| Nothing for MCP connections | MCP server connections and tool calls | MCP connection monitoring |
| Nothing for reachable credentials | What the agent's account could reach but did not use | Permission inventory (`docs/design/reachable-set-inventory.md`) |

"Planned" means a design or a documented prerequisite exists. It is not a delivery date and none of it is active.
