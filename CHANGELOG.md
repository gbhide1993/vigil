# Changelog

Product versions follow the installer (Vigil-Setup.exe). The VS Code extension has its own changelog in vigil-vscode/CHANGELOG.md.
## 0.9.3 (unreleased)

### Fixed
- ETW tier: events outside the watched folders, the credential paths and the agents' own folders (`~/.claude`, `~/.codex`) are now decided from memory, before the agent lookup and before anything reaches the database, and are only counted. A recognised agent's desktop app writing its own cache, crash-report and log files produced thousands of events a second, each costing a SELECT, an UPDATE and a commit, and delayed the aggregator's writes (a batch of 19 events took 168 s on one machine). `GET /health` returns `file_watcher_tier` and `file_events_not_recorded` (dropped by reason, and outside-scope counts, since start), and the per-session PDF prints them when they are not zero.
- An agent's database id is remembered, and its `last_seen` and `pid` are written at most once a minute instead of on every file event. Many first events for a new agent arriving together no longer create duplicate agent rows.
- ETW device paths (`\Device\HarddiskVolume3\...`) are converted to drive-letter paths before scope checks and storage.
- The activity check for ignored helper processes is cheap again: a session made of conhost and Vigil spawns no longer takes seconds to check. The current-session call runs on a read-only connection instead of the writer's.
- The ETW filter also lets through persistence locations, so a write that makes code run later is still recorded wherever it happens: the user's Startup folder, PowerShell profiles (`profile.ps1`, `Microsoft.PowerShell_profile.ps1`, `Microsoft.VSCode_profile.ps1` under `WindowsPowerShell` or `PowerShell`), the shell profiles in the home folder (`.bashrc`, `.bash_profile`, `.bash_login`, `.profile`, `.zshrc`, `.zprofile`, `.zshenv`) and `~/.gitconfig`. A write there outside a watched folder raises the usual out-of-scope alert.
- The post-install launch of Vigil runs as the user who started Setup (`runasoriginaluser`), not elevated.

### Added
- `VLAW_FILE_WATCHER` (`auto`, `etw`, `native`, `polling`) forces the file-watching tier, for comparing them on one machine.

### Changed
- The ETW tier no longer records every change a recognised agent makes anywhere on the computer; the report note and `docs/COVERAGE.md` say what it records now. Changes outside the watched places are counted, not stored, so an out-of-scope alert is no longer raised for them.

### Known limits
- Still not recorded by the ETW tier outside the watched places: a change to a project's own `.vscode/settings.json`, `.cursor/config` or `.mcp.json` in a folder that is not watched. Red Line 7b (a config write followed by an execution within 2 seconds) can then only start from the watched places and `~/.claude`, and a file write elsewhere no longer counts as its trigger (a process spawn still does). Red Line 8 (`.mcp.json`) also needs the MCP watcher, which is off in this version.
- The never-scope and credential folders the ETW filter lets through are read at start; a change to them in the policy file needs a restart (watched folders added or removed in Settings apply at once).
- Events already stored with the raw device path are not rewritten (stored events are part of the hash chain).
- The counts of dropped and outside-scope changes are for the whole backend run, not per session, and reset when it restarts.
- The 168 s batch time seen on one machine was not reproduced in a test; the load test shows the flood no longer reaches the database or drops real events, but another cause of slow writes on that machine is not ruled out.

## 0.9.2 (not released; superseded by 0.9.3)

### Fixed
- File writes that two or more agents could have made, and that nothing narrows down (not in `~/.claude` or `~/.codex`, and the open-handle check does not name one process), are no longer given to whichever agent came first. They are recorded under the agent `unattributed` with confidence low, and shown as "<n> agents active, cannot tell which wrote this" in the dashboard, and the session and daily reports. With one agent running, nothing changes.
- The Activity rule compares the ignored helper processes (conhost, wslhost, werfault, Vigil's own) by executable base name, so a recorded command line such as `\??\C:\Windows\system32\conhost.exe 0x4` is ignored like `conhost`.
- The dangerous-command Red Line no longer fires on Claude Code's own shell wrapper (`bash.exe -c source <home>\.claude\shell-snapshots\...`) when the home folder has a space in it or the snapshot path is quoted. Real dangerous commands, inside or outside that wrapper, are still flagged.
- Friction findings: `ping -n N 127.0.0.1` (or `localhost`) is treated as a sleep, not a retried command. A `retry_loop` on a process is labelled by the program (`filepath` is the executable, and `command_name` is added), never by a trailing argument such as `-q`; the full command line stays in the evidence text.
- Uninstaller: every step it runs now uses `Exec` (no `ExecAsOriginalUser`), it removes the `electron.app.Vigil` startup entry, and a step that has nothing to do (value or folder already gone, helper script missing after a partial uninstall) no longer stops the steps after it, so it can be run again.

### Known limits
- Unattributed writes show up as their own agent in the agent and session lists, so per-agent counts are lower than before wherever two agents ran at once. Which agent wrote a change is still not known; this stops guessing, it does not find out.
- With one agent running, a change you make yourself is still shown under that agent, and with ETW off every attribution other than the `~/.claude` and `~/.codex` location rule and a single open-handle match remains a best guess.
- The wrapper rule only recognises Claude Code's `shell-snapshots\snapshot-*.sh` form. Other wrappers are still judged as one command line.
- The ping rule only covers `ping -n N` to `127.0.0.1`, `localhost` or `::1`.
- The uninstaller runs as the account that runs it. If that is an administrator other than the person who uses Vigil, that person's startup entry and `%LOCALAPPDATA%\V-LAW` folder belong to another account and are not removed. The installer script was checked by tests that read it; the uninstaller itself has not been run.

## 0.9.1 (released 2026-10-21)

### Fixed
- A session opened only because Vigil found an agent process already running at startup, with no activity after it, is no longer shown as the current session, as a session in the lists, or counted in "recording since". The row is kept and its report still opens by id.
- Session report: says when Vigil began watching while the agent was already running (start time and duration are from when watching began), counts only real spawns, shows "Already running when watching began: N" separately, lists up to 20 processes with their PIDs, and its footer now matches the report's coverage section.
- Session lists and the current-session call now carry `has_activity`; the current-session call also carries `resumed`.
- File changes under `~/.claude` (Claude Code's checkpoint files) are attributed to Claude Code, and changes under `~/.codex` to Codex, when that agent is running, instead of to whichever agent the best-guess heuristic found first. They are labelled "attributed to <agent> by file location" (event source `path`, confidence medium); every other path keeps the heuristic. Vigil's own `vigil.exe` and `vigil-backend.exe` spawns no longer count as agent activity.
- A session that only started an agent (for example the Codex VS Code extension launching codex.exe and its console host) no longer counts as having real activity: a spawn counts only if it is a new tool or shell process, not the agent's own exe and not conhost, wslhost or werfault. Such sessions are hidden from the current session, flagged `has_activity` false in the session lists, and the session history used by the VS Code extension (`/mcp/sessions`) now returns `has_activity`, `resumed`, `idle` and `last_activity_at` for every session.
- An open session with no event for more than 5 minutes is reported as idle (`status` "idle" and `last_activity_at` on the current-session call, `idle` and `last_activity_at` on session lists). Its report says "Idle since <time>" with the duration counted to that time. Display only: nothing is written and the idle sweep stays off.

### Changed
- Friction findings: `retry_loop` now means the same file written 5 or more times, or the same command spawned 3 or more times, within 10 minutes. It used to count any 3 events of one type. The finding text now says what repeated.
- Console hosts, git, shells and Claude cache and temp files are skipped by `retry_loop` and `rapid_revert`, as are generated and build-output folders (dist, build, out, win-unpacked, node_modules) and editor and tool temp files (`.tmp.`, Vite `.timestamp-`, Office `~$`, vim `.swp`).
- The `session_abandoned` finding is no longer produced, because Vigil does not record commits.

### Known issues
- Uninstall shows a runtime error (ExecAsOriginalUser); fixed in 0.9.2.

### Known limits
- The scheduled idle sweep is still off (disabled in e821731 pending an event-loop audit), so sessions still close lazily and durations and counts can be off.

## 0.9.0 (October 2026)
### Added
- Signed evidence bundle (Export page) and a standalone offline verifier (verifier/vigil_verify.py).
- Optional external timestamp of the anchor hash (RFC 3161), off by default.
- Local evidence anchors (hourly, at export and after a monitoring gap) and a hash chain over the recorded events, both checked by Vigil itself.
- Coverage and limits wording in reports and docs matched to actual behaviour.
### Changed
- The native launcher binds to 127.0.0.1 by default, and the Docker setup publishes its port on 127.0.0.1 only.
- Agent status separates running, open (idle) and active.
- The installer can remove the keys folder on uninstall (when you choose to delete stored data) and generates the download manifest.
### Known limits
- Windows only; the installer is unsigned.
- Nine Red Line rules exist; five can fire. The two that need file reads and the two that need network or MCP monitoring cannot fire in this version.
- File reads, network connections and MCP connections are not monitored.
- Processes are checked about every 30 seconds.
- Records are not protected against someone who can edit the local database; only the event chain is checked, and by Vigil itself.
- The 30-day trial status is reported by the health endpoint only and is not enforced.

## Historical (July 2026), not re-verified against 0.9.0
The entries below were written during the beta and may not match current behaviour. See the README for what fires today.

## v0.2.0-beta — July 2026

### Added
- **CVE-aware Red Line detection** — RL7 (environment variable redirect, 
  matches CVE-2026-21852 pattern) and RL7b (malicious config execution, 
  matches CVE-2025-59536 pattern), with per-process scanning to correctly 
  attribute the exact process, not just the first match found
- **RL8: MCP auto-approval detection (does not fire in 0.9.0)** — extends CVE-2026-21852 coverage 
  to the MCP server attack surface, session-gated to early-project usage 
  where the exploit actually applies
- **Session Verification Report** — independently compares OS-level 
  observed file activity against the agent's own self-reported 
  `.jsonl` session log; surfaces discrepancies as a new alert type
- **Agent version CVE checker** — flags installed Claude Code versions 
  vulnerable to known, disclosed CVEs (verified against NVD, GitHub 
  Security Advisories, and Check Point Research)
- **Cross-agent correlation** — detects when two different agents touch 
  the same file with no commit between them, and when credential files 
  are accessed by multiple different agents within 24 hours
- **Config Auditor** — reads your actual Claude Code permissions config, 
  compares against 9 recommended protection patterns, shows exactly 
  what's missing with plain-English reasoning and severity
- **Daily proof-of-value digest** — "days clean" streak, agents watched, 
  files monitored, destinations verified, and config coverage shown 
  directly on the Live Feed dashboard, even on days with no alerts
- **RL3 checkpoint correlation** — hidden cache directory writes are now 
  checked against active session state; normal `/rewind` checkpoint 
  activity fires as informational, not a high-severity alert

### Fixed
- **Critical: event-loop blocking** — synchronous psutil calls in 
  ProcessWatcher and NetworkWatcher were blocking the entire backend 
  under load, causing the server to stop responding to any request. 
  Moved to thread executor.
- **Duplicate backend process spawning** — added spawn guard and 
  Electron single-instance lock to prevent multiple backend instances 
  running simultaneously on launch
- **Attribution performance** — added PID-based caching to agent 
  attribution logic, reducing repeat-poll cost
- **MAD scoring silent-zero edge case** — Layer 2b now falls back to 
  percentage-deviation scoring when historical variance is exactly 
  zero, instead of silently missing anomalies for agents with very 
  consistent behavior

### Known Limitations
- CVE tracking currently covers Claude Code only; Cursor and Copilot 
  are not yet researched (not confirmed clean, simply unresearched)
- Cross-agent correlation has no git-commit awareness yet — may flag 
  legitimate multi-agent workflows where a commit occurred between touches
- Config Auditor and Session Verification Report have been tested on 
  a limited number of machines; broader reliability across different 
  Claude Code install methods is not yet confirmed

## v1.0.0-beta — July 2026

### Added
- System tray icon with green/amber/red status states
- Agents recognised by process name: Claude Code, Cursor, GitHub Copilot, Codex and Agentforce (core/attributor.py KNOWN_AGENTS)
- Nine Red Line rules, RL1 to RL8 plus RL7b (non-disableable safety floor; five can fire in 0.9.0, see the README)
- Layer 2a anomaly detection — works from session 1
- Layer 2b MAD scoring — activates from session 3
- Desktop toast notifications on new alerts
- 9AM daily digest
- Agent approval workflow (Approve/Block)
- One-click Windows installer (no Docker required)
- Audit PDF + SIEM JSON export

### Known Limitations
- Windows only (macOS planned)
- Unsigned installer (SmartScreen warning on install)
- 30-day trial license included (the status is shown by the health endpoint only; nothing is enforced in 0.9.0)

## Roadmap

### v1.1 (post-beta)
- Noise floor tuning improvements
- macOS support
- Code-signed installer
- Layer 3 local SLM behavioral clustering
