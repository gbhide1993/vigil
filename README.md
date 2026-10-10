# Vigil — AI Session Monitor

See what Claude Code, Cursor, Codex, and GitHub Copilot actually do on your machine.
OS-level evidence. Runs locally. Nothing leaves your machine.

## What it shows

The sidebar updates live while your AI agent works:

- **Agent** — which agent is active (Claude Code, Cursor, Copilot, Codex)
- **Duration** — how long the session has been running
- **Status** — active or idle
- **Files touched** — files the agent created, changed, moved or deleted (file reads are not recorded)
- **Friction Signals** — patterns like retry loops or rapid reverts
- **Red Lines** — high-risk events: changes to credential files, suspicious commands, risky configuration changes

## How to install

1. Install this extension
2. The Vigil backend downloads and installs automatically on first launch (one-time, ~110 MB)
3. Start Claude Code, Cursor, Codex, or Copilot — your session appears in the sidebar within 30 seconds

**Windows SmartScreen note: ** When the backend installer runs, Windows may show a security warning. Click **More info** → **Run anyway**. This is expected — the installer is not yet code-signed.

## How it works

Vigil runs a local backend that monitors your machine at the OS level — independently of what the AI agent reports. File changes (created, changed, moved or deleted; reads are not recorded), process spawns with their command text (secrets are redacted on a best-effort basis), and changes to credential files are captured and attributed to the active agent session. Processes are checked about every 30 seconds, so a program that starts and finishes between checks is not recorded. Network monitoring is planned; it is off in this version. Everything is stored locally in SQLite. No data leaves your machine.

## Red Lines

There are nine red-line rules (RL1 to RL8, plus RL7b). They cannot be disabled, but only five can fire in this version, because the other four depend on signals Vigil does not currently produce.

Active:

- Changes inside your `.ssh` directory
- Claude's hidden cache folder written when no session is active
- Agent launches a sensitive command (`curl`, `wget`, `ssh`, `nc`, `git push --force`, recursive deletes, and similar)
- `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` pointed at an unrecognized host (checked about every 30 seconds)
- A project config file (`.claude`, `.cursor`, `.vscode`) written and then followed by a spawn or write elsewhere

Not active in this version:

- `.env` file read outside the project and cross-project file read (file reads are not recorded)
- Connection to an unrecognized network destination (network monitoring is off)
- MCP server auto-approval (MCP connection monitoring is off)

See [docs/COVERAGE.md](docs/COVERAGE.md) for what Vigil does and does not see.

## Requirements

- Windows 10 or 11
- VS Code 1.85+
- Internet connection for first install only

## Supported agents

Claude Code · Cursor · Codex · GitHub Copilot
