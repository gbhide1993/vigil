# Vigil

## Verify Your Coding Agent.

Claude Code, Cursor, GitHub Copilot and Codex do a lot on your machine.

**Vigil gives you independent OS-level evidence of what actually happened.**

![Vigil in action](https://download.getvvault.com/vigil_demo.gif)

---

Agent: *"I fixed it."*
Vigil: *Here's what the machine observed.*

Agent: *"I didn't access anything unusual."*
Vigil: *Here's the evidence.*

Agent: *"I only changed what was necessary."*
Vigil: *Here's the session record.*

> **Don't just trust what your coding agent says it did. Verify it.**

---

## What Vigil shows you

**🔌 MCP activity** — every MCP server call your agent makes

**🌐 Network connections** — outbound connections initiated during the session

**⚙️ Process activity** — commands and processes spawned by your agent

**📄 File activity** — files read, written, or deleted

**🚨 Red Lines** — hard limits you define; Vigil flags anything that crosses them

**🔄 Friction signals** — unusual patterns worth a second look

**🔍 Session evidence** — a timestamped record you can query

---

## How it works

Vigil sits at the OS level, independent of your coding agent. It doesn't rely on what the agent reports — it observes what the machine actually does.

The Vigil VS Code sidebar connects to a local backend that monitors file activity, network connections, and process spawns in real time. Claude Code (and other agents) can query Vigil directly via MCP to get a record of their own session activity.

**Vigil observes. Claude reasons. Developer decides.**

---

## Works with

- Claude Code
- Cursor
- GitHub Copilot
- Codex
- Any agent that touches your machine

---

## Get started

**[Download Vigil](https://download.getvvault.com/Vigil-Setup.exe)** — installs the local tray app and backend in under two minutes.

1. Run `Vigil-Setup.exe` — start the tray app before opening VS Code
2. Install this extension
3. Open the Vigil sidebar in VS Code
4. Start a coding agent session — Vigil begins recording immediately

---

## Red Lines

Red Lines are conditions you define that Vigil should never let pass silently.

Examples:
- Network connection to an unexpected external host
- Write to a file outside your project directory
- Process spawn that looks like an exfiltration tool

When a Red Line fires, Vigil flags it in the sidebar. You decide what to do next.

---

## Privacy

Vigil runs entirely on your machine. Nothing is sent to any external server. No telemetry. No cloud dependency. The local backend runs on port 7422 and is only accessible from localhost.

You can verify this with any network monitoring tool.

---

## Requirements

- Windows 10 or 11
- VS Code 1.80+
- Vigil tray app installed and running ([download here](https://download.getvvault.com/Vigil-Setup.exe))

---

[getvvault.com](https://getvvault.com) · [GitHub](https://github.com/gbhide1993/vigil)
