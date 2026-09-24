# Vigil — AI Agent Monitor Plugin for Claude Code

Vigil captures **every file touch, network connection, and process spawn** your Claude Code agent makes — independently of agent self-reporting — and generates a tamper-evident PDF audit report you can share with security and compliance teams.

## What it does

When Vigil is running alongside Claude Code, it:

- **Monitors file activity** — records every read/write the agent makes, flags out-of-scope paths and credential files (`.env`, SSH keys, AWS credentials)
- **Tracks network connections** — logs all outbound connections, flags anything not in your approved policy
- **Records process spawns** — captures every subprocess the agent launches
- **Generates session PDF reports** — a one-click audit trail with timestamps in your local timezone, color-coded labels, and a policy legend

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
- Live event feed (files, network, processes)
- **Download Session Report (PDF)** button

## PDF Report

The session PDF includes:

| Section | Contents |
|---|---|
| Header | Session ID, agent name, start time (local TZ), duration |
| Summary | Files touched, network connections, process spawns, red lines |
| File Events | Path, event type, timestamp — with `[OK]`, `[OUTSIDE SCOPE]`, `[CREDENTIAL PATH]` labels |
| Network Events | Host:port, timestamp — with `[APPROVED]`, `[NOT IN POLICY]` labels |
| Process Events | Command line, timestamp |
| Red Lines | Policy violations with full details |
| Legend | Label definitions |

> **"Evidence is captured independently of agent self-reporting"** — the Vigil backend uses OS-level file system events (ReadDirectoryChangesW / ETW), not agent logs.

## Policy configuration

Vigil policy is configured via a JSON file. Default location: `%LOCALAPPDATA%\V-LAW\policy.json`

Key policy fields:
- `scope_directories` — paths the agent is permitted to write in
- `approved_network_destinations` — hostnames/IPs the agent may connect to
- `approved_mcp_servers` — MCP server processes that should not be flagged
- `credential_path_patterns` — glob patterns for sensitive files

## Privacy

Vigil runs **entirely locally**. No event data leaves your machine. The PDF is generated locally and never uploaded anywhere.

## Support

- Website: [getvvault.com](https://getvvault.com)
- GitHub: [github.com/gbhide1993/Vvault](https://github.com/gbhide1993/Vvault)
- Email: hello@getvvault.com
