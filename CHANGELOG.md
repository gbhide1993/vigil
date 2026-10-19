# Changelog

Product versions follow the installer (Vigil-Setup.exe). The VS Code extension has its own changelog in vigil-vscode/CHANGELOG.md.

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
