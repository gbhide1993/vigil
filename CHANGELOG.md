# Changelog

## v0.2.0-beta — July 2026

### Added
- **CVE-aware Red Line detection** — RL7 (environment variable redirect, 
  matches CVE-2026-21852 pattern) and RL7b (malicious config execution, 
  matches CVE-2025-59536 pattern), with per-process scanning to correctly 
  attribute the exact process, not just the first match found
- **RL8: MCP auto-approval detection** — extends CVE-2026-21852 coverage 
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
  attribution logic, reducing repeat-poll cost by roughly 1300x
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
- Real-time monitoring of Claude Code, Cursor, Copilot
- Six Red Line rules (non-disableable safety floor)
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
- 14-day trial license included

## Roadmap

### v1.1 (post-beta)
- Noise floor tuning improvements
- macOS support
- Code-signed installer
- Layer 3 local SLM behavioral clustering
