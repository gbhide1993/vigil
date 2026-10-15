# Vigil — AI Agent Monitor Plugin for Claude Code

Vigil records the **file changes, process spawns and changes to credential files** your Claude Code agent causes, independently of agent self-reporting, and generates a PDF session report you can share with security and compliance teams. The report states what is not covered: file reads are not recorded, and network monitoring is planned and off in this version.

## What it does

When Vigil is running alongside Claude Code, it:

- **Monitors file activity** — records files the agent creates, changes, moves or deletes (file reads are not recorded), flags changes outside the watched folders and changes to credential files (`.env`, SSH keys, AWS credentials); reading a credential file is not detected
- **Network monitoring is planned** — network connections are not monitored in this version, so unrecognised-destination alerts are not produced
- **Records process spawns** — records the processes the agent launches, with command text (secrets redacted on a best-effort basis). Processes are checked about every 30 seconds, so one that starts and finishes between checks is not recorded
- **Generates session PDF reports** — a one-click session report with timestamps in your local timezone, color-coded labels, and a policy legend

## Requirements

- **Windows 10/11 or Windows Server 2019+** (macOS/Linux support coming)
- **Vigil backend** must be running locally at `http://127.0.0.1:7422`
  - Download the Vigil desktop app from [getvvault.com](https://getvvault.com)
  - Or install the **Vigil VS Code extension** (ID: `getvvault.vigil`) which manages the backend automatically

## Installation

Install the Vigil backend first, then enable this plugin:

```bash
claude plugin install vigil@claude-community
```

The plugin connects to the Vigil backend MCP server at `http://127.0.0.1:7422/mcp`.

## Usage

Once installed and the Vigil backend is running, the plugin provides:

### Session Report skill

Ask Claude to generate a session audit report at any time:

```
/vigil:vigil-session-report
```

Or just ask naturally:
- "Generate my Vigil session report"
- "What files did the agent touch this session?"
- "Download the audit PDF"

### VS Code sidebar (requires Vigil extension)

The Vigil VS Code extension shows a live sidebar with:
- Active session status and agent name
- Live event feed (files, processes)
- **Download Session Report (PDF)** button

## PDF Report

The session PDF includes:

| Section | Contents |
|---|---|
| Header | Session ID, agent name, start time (local TZ), duration |
| Summary | Files touched, network connections (shown as "off" while network monitoring is off), process spawns, red lines |
| File Events | Path, event type, timestamp — with `[OK]`, `[OUTSIDE SCOPE]`, `[CREDENTIAL PATH]` labels |
| Network Events | Not recorded in this version (network monitoring is off); the report says so. Entries and `[APPROVED]` / `[NOT IN POLICY]` labels appear only once network monitoring exists |
| Process Events | Command line, timestamp |
| Red Lines | Policy violations with full details |
| Legend | Label definitions |

> **"Evidence is captured independently of agent self-reporting"** — the Vigil backend uses OS-level file system events (ReadDirectoryChangesW / ETW), not agent logs.

## Policy configuration

Vigil policy is configured via a JSON file. Default location: `%LOCALAPPDATA%\V-LAW\policy.json`

Key policy fields:
- `scope_directories` — paths the agent is permitted to write in
- `approved_network_destinations` — hostnames/IPs the agent may connect to (used once network monitoring is available; not enforced in this version)
- `approved_mcp_servers` — MCP server processes that should not be flagged
- `credential_path_patterns` — glob patterns for sensitive files

## Privacy

The Export page can produce a signed evidence bundle that `verifier/vigil_verify.py` checks offline. It shows the bundle was not edited after export by anyone without the signing key (readable by the Windows user Vigil runs as); it does not show who exported it, that the record is complete, or anything about events after the newest timestamp.

Vigil runs locally and uploads no event data. The outbound paths are an optional Slack or Teams webhook that sends a daily digest (counts and a summary sentence), only if you save a URL, and an optional external timestamp (off by default) that sends only a 32-byte anchor hash to the service you choose, a second outbound connection; a token covers only what existed when the anchor was made. The native app listens on 127.0.0.1 only. The PDF is generated locally and never uploaded anywhere.

## Support

- Website: [getvvault.com](https://getvvault.com)
- GitHub: [github.com/gbhide1993/Vvault](https://github.com/gbhide1993/Vvault)
- Email: hello@getvvault.com
