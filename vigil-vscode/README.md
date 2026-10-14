# Vigil

## Verify Your Coding Agent.

Claude Code, Cursor, GitHub Copilot and Codex do a lot on your machine.

**Vigil keeps an independent, OS-level record of the file changes and processes the machine observed.**

![Vigil in action](https://download.getvvault.com/vigil_demo.gif)

---

Agent: *"I fixed it."*
Vigil: *Here are the file changes and processes the machine recorded.*

Agent: *"I only changed what was necessary."*
Vigil: *Here is the session record.*

> **Don't just trust what your coding agent says it did. Check it against what the machine recorded.** Vigil sees file writes, deletes and process spawns. It does not see everything (see Limits below).

---

## What Vigil shows you

**📄 File activity**: files created, changed, moved or deleted in the folders Vigil watches. File reads are not recorded.

**⚙️ Process activity**: commands and processes spawned by your agent, checked about every 30 seconds (a process that starts and ends between two checks is missed).

**🔑 Credential-path flags**: a change to a path that looks like a credential (`.env`, `.ssh`, `.aws`, `.pem`, `.key`) is flagged.

**🚨 Red Lines**: fixed safety rules that Vigil flags in the sidebar (see Red Lines below).

**🔄 Friction signals**: unusual patterns worth a second look.

**🔍 Session history**: a timestamped record of each session that you can query and export as a PDF.

**Not in this version:** network connection monitoring and MCP connection monitoring are off. Nothing in the sidebar or in reports is based on them, and unrecognised-destination or MCP alerts are not produced.

---

## How it works

Vigil sits at the OS level, independent of your coding agent. It does not rely on what the agent reports. It records what it observes on the machine.

The Vigil VS Code sidebar connects to a local backend that records file changes and process spawns. Folders you add as project folders in the Vigil app are watched, plus `~/.ssh` and Claude's checkpoint folder. Generated folders (`node_modules`, `.venv`, `dist`, `build` and similar) are ignored. Claude Code and other agents can also read their own session record through Vigil's local, read-only MCP endpoint. That endpoint only serves Vigil's records. It is not monitoring of MCP servers.

**Vigil observes. Claude reasons. Developer decides.**

---

## Works with

Agents Vigil recognises by process name:

- Claude Code
- Cursor
- GitHub Copilot
- Codex

Other agent-like processes may be flagged as an "unidentified agent" on a best-effort basis. Vigil does not claim to see every agent on your machine.

---

## Get started

**[Download Vigil](https://download.getvvault.com/Vigil-Setup.exe)** installs the local tray app and backend.

1. Run `Vigil-Setup.exe` and start the tray app before opening VS Code
2. Install this extension (Marketplace id `vvault.vigil-ai-monitor`)
3. Open the Vigil sidebar in VS Code
4. Start a coding agent session. Vigil records file changes and process spawns while an agent is running.

### If Vigil is not installed yet

On first launch the extension can download the installer for you (about 110 MB) from `download.getvvault.com`, check its SHA256 against the value in the download manifest, and run it silently. Windows will ask for administrator approval. The SHA256 in that manifest comes from the same server as the installer, so it protects against a corrupted download, not against a compromised server. If you prefer, install Vigil yourself first and the extension will not download anything.

### Windows SmartScreen and the unsigned installer

The Vigil installer is not code-signed yet. Windows SmartScreen may show "Windows protected your PC" and the administrator prompt will show an unknown publisher. Before you run it:

1. Compute the installer's hash: `Get-FileHash .\Vigil-Setup.exe -Algorithm SHA256` in PowerShell.
2. Compare it with the SHA256 published with the release (the `.sha256` file next to the installer). Obtain that value separately from the download itself.
3. Run the installer only if they match. If SmartScreen appears, choose "More info" and then "Run anyway".

---

## Red Lines

Red Lines are fixed safety rules. They cannot be disabled or edited. When one fires, Vigil flags it in the sidebar and you decide what to do next. The rules that can fire in this version:

- A file under a `.ssh` directory is created, changed, moved or deleted (the alert says "SSH directory changed"; reading a key is not detected)
- A write to Claude's hidden checkpoint folder when the agent has no active or recent session
- A process whose command matches the sensitive list (for example `curl`, `wget`, `ssh`, `nc`, force push, recursive delete, encoded PowerShell, download-and-execute)
- `ANTHROPIC_BASE_URL` or `OPENAI_BASE_URL` set to an unrecognised host
- A project config file (`.claude`, `.cursor`, `.vscode`) written and then a spawn or write elsewhere shortly after

Four more rules exist but do not fire in this version: two need file-read events, which are not recorded on Windows (a `.env` file read outside the project, a cross-project read), and two need network or MCP monitoring, which are off. Separately, you can set watched folders and credential paths in Vigil's policy, and changes to credential-looking files in watched folders raise alerts.

---

## Privacy and data flow

- Vigil records file writes and deletes, process spawns (command lines, with best-effort secret redaction), and credential-path flags.
- Vigil does not store file contents, diffs or prompts.
- Everything is stored locally in a SQLite database under `%LOCALAPPDATA%\V-LAW`.
- The native app listens on `127.0.0.1` only. The local API has no authentication, so never expose port 7422 to a network. The Docker setup publishes the port on `127.0.0.1` only, but inside the container the server listens on all interfaces.
- Vigil uploads no event data. The outbound paths are an optional Slack or Teams daily-digest webhook (counts and a summary sentence), only if you save a URL in Settings, and an optional external timestamp (off by default) that, once you turn it on and set a service address, sends only a 32-byte hash of an anchor to that service. That is a second outbound connection; no events, paths or names are sent, and a token covers only what existed when the anchor was made.
- There is no automatic retention yet: events stay in the database until you remove them.
- The uninstaller asks before deleting the stored evidence.

---

## Limits

- Vigil does not protect its records against someone who can edit the local database. The report's hash chain is checked by Vigil itself and is not anchored anywhere outside your machine.
- Without the optional ETW tier (needs Administrator), file changes are attributed to the agent running at the time on a best-guess basis. A change you make yourself while an agent is running may be shown under the agent.
- File reads are not recorded. Network and MCP connections are not monitored.
- Processes are checked about every 30 seconds, so short-lived processes can be missed.
- Windows only.

---

## Requirements

- Windows 10 or 11
- VS Code 1.85+
- Vigil tray app installed and running ([download here](https://download.getvvault.com/Vigil-Setup.exe))

---

[getvvault.com](https://getvvault.com) · [GitHub](https://github.com/gbhide1993/vigil)
