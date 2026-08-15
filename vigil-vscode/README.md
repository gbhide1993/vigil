# Vigil — AI Session Monitor

See what Claude Code, Cursor, and GitHub Copilot actually do on your machine.
OS-level evidence. Runs locally. Nothing leaves your machine.

## What it shows

The sidebar updates live while your AI agent works:

- **Agent** — which agent is active (Claude Code, Cursor, Copilot)
- **Duration** — how long the session has been running
- **Status** — active or idle
- **Files touched** — files the agent read or wrote
- **Friction Signals** — patterns like retry loops or rapid reverts
- **Red Lines** — high-risk events: unexpected network connections, credential access, suspicious commands

## How to install

1. Install this extension
2. The Vigil backend downloads and installs automatically on first launch (one-time, ~110 MB)
3. Start Claude Code, Cursor, or Copilot — your session appears in the sidebar within 30 seconds

**Windows SmartScreen note:** When the backend installer runs, Windows may show a security warning. Click **More info** → **Run anyway**. This is expected — the installer is not yet code-signed.

## How it works

Vigil runs a local backend that monitors your machine at the OS level — independently of what the AI agent reports. File writes, network connections, process spawns, and credential access are all captured and attributed to the active agent session. Everything is stored locally in SQLite. No data leaves your machine.

## Red Lines

Eight rules that always run and cannot be disabled:

- AI agent reads SSH keys or `.env` files outside the project
- Network connection to an unrecognized destination
- Agent launches `curl`, `wget`, `ssh`, or `nc`
- `ANTHROPIC_BASE_URL` redirect detected (potential prompt injection)
- Untrusted MCP server auto-approved

## Requirements

- Windows 10 or 11
- VS Code 1.85+
- Internet connection for first install only

## Supported agents

Claude Code · Cursor · GitHub Copilot
