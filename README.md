# Vigil — AI Session Monitor

See what Claude Code, Cursor, Codex, and GitHub Copilot actually do on your machine.
OS-level evidence. Runs locally. Vigil uploads no event data. Two optional outbound paths, both off until you set them: the daily-digest webhook, and an external timestamp that sends only a 32-byte anchor hash.

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

Vigil runs a local backend that monitors your machine at the OS level — independently of what the AI agent reports. File changes (created, changed, moved or deleted; reads are not recorded), process spawns with their command text (secrets are redacted on a best-effort basis), and changes to credential files are captured and attributed to the active agent session. Processes are checked about every 30 seconds, so a program that starts and finishes between checks is not recorded. Network monitoring is planned; it is off in this version. Everything is stored locally in SQLite. Vigil uploads no event data. There are two optional outbound paths, both off until you set them: the daily-digest webhook, and an external timestamp that sends only a 32-byte anchor hash.

## Red Lines

There are nine red-line rules (RL1 to RL8, plus RL7b). They cannot be disabled, but only five can fire in this version, because the other four depend on signals Vigil does not currently produce.

Active:

- A file in your `.ssh` directory is created, changed, moved or deleted (the alert says "SSH directory changed"; reading a key is not detected)
- Claude's hidden cache folder written when no session is active
- Agent launches a sensitive command (`curl`, `wget`, `ssh`, `nc`, `git push --force`, recursive deletes, and similar)
- `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` pointed at an unrecognized host (checked about every 30 seconds)
- A project config file (`.claude`, `.cursor`, `.vscode`) written and then followed by a spawn or write elsewhere

Not active in this version:

- `.env` file read outside the project and cross-project file read: both need file-read events, which are not recorded on Windows in this version, so they cannot fire (the rules stay in the code)
- Connection to an unrecognized network destination (network monitoring is off)
- MCP server auto-approval (MCP connection monitoring is off)

See [docs/COVERAGE.md](docs/COVERAGE.md) for what Vigil does and does not see.

## What Vigil contacts over the network

Nothing, by default. The backend listens on localhost only, the interface and its fonts are served
from your own machine, and there is no update check, telemetry upload or license server call.

The one exception is the daily summary webhook (Slack, Teams or any webhook URL). It is off until you
save a URL in Settings; then Vigil sends the daily summary text to exactly that URL. Leave the URL empty
and nothing is sent. The full list is in `docs/COVERAGE.md` ("Network contact").

The second exception is the optional external timestamp (Settings, off by default). When you turn it on and
set the address of an RFC 3161 timestamp service, Vigil sends only a 32-byte hash of an anchor to that service.
No events, file paths or names leave the machine. This is a second outbound connection. A returned token covers
only what existed when that anchor was made, not later events, and without a certificate you supply its
signature is not checked (it is marked "timestamp_unverified_signature").

## Evidence bundle and verifier

The Export page can produce a signed evidence bundle (a zip) for a day: the events with their chain rows, the anchors that bind them, any stored timestamp tokens and a manifest signed with a per-install key. verifier/vigil_verify.py checks it offline, with no network and no Vigil code. It shows the bundle was not edited after export by anyone without the signing key, and that the exported events re-hash into the chain the anchors recorded. It does not show who exported it (the key is readable by the Windows user Vigil runs as), that the record is complete (file reads, network and MCP calls are not recorded), or anything about events after the newest timestamp. Alerts, sessions and audit entries are not integrity-protected in this version. The format is in `docs/design/evidence-bundle-spec.md`.

## Requirements

- Windows 10 or 11
- VS Code 1.85+
- Internet connection for first install only

## Supported agents

Claude Code · Cursor · Codex · GitHub Copilot
