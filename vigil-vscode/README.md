# Vigil — AI Session Monitor

**See what Claude Code, Cursor, and Copilot actually do on your machine. OS-level evidence. Runs locally. Nothing leaves your machine.**

---

![Vigil sidebar showing live session with Red Line alert](https://download.getvvault.com/vigil_view_evidence.png)

---

## The problem

AI coding agents read files, run commands, and modify your code.

Most of the time that's fine. But there are moments when "the agent said it worked" isn't enough.

**"It said the bug was fixed. But the tests are still failing."**
Did the agent change the wrong file? Retry the same broken approach? Revert something that was working?

**"I asked it to change one file. Why did it touch 14?"**
Agents expand scope while solving problems. Sometimes that's necessary. Sometimes it's not.

**"It's been working for 20 minutes. Is it actually making progress?"**
Agents can get stuck in loops — edit, test, fail, revert, retry — without surfacing that to you.

**"Did the AI agent access something it shouldn't have?"**
When something looks suspicious, the agent's own explanation isn't enough. You need independent evidence.

**"Who — or what — actually made this change?"**
AI-assisted development needs an evidence trail. Knowing the developer who started a task may not be enough anymore.

---

> **The question is no longer just "what did the agent say it did?"**
>
> **It's "what did the machine actually observe?"**

That's the problem Vigil is built around.

---

## What Vigil shows

The sidebar updates live while your AI agent works:

- 🤖 **Agent** — which agent is active (Claude Code, Cursor, Copilot, Codex)
- ⏱ **Duration** — how long the session has been running
- 🟢 **Status** — active or idle
- 📄 **Files touched** — every file the agent read or wrote
- ⚠️ **Friction Signals** — patterns like retry loops, rapid reverts, repeated failures
- 🚨 **Red Lines** — high-risk events: unexpected network connections, credential access, suspicious commands

![Red Line alert firing in status bar](https://download.getvvault.com/vigil_redline.png)

---

## Red Lines

Red Lines are non-negotiable alerts. When one fires, Vigil notifies you immediately and logs the full evidence.

Current Red Line triggers:

- 🔴 Network connection to an unrecognised destination
- 🔴 Base64-encoded command in a bash process spawn
- 🔴 Credential file access (`.env`, SSH keys, token stores)
- 🔴 Process spawn outside expected working directory
- 🔴 Outbound connection during a supposedly offline task

Every Red Line includes a **View Evidence** button with the raw OS-level event — timestamp, process, destination, and full context.

![View Evidence panel showing Red Line detail](https://download.getvvault.com/vigil_view_evidence.png)

---

## How it works

Vigil runs a local backend that monitors your machine at the OS level — independently of the agent. It does not hook into Claude Code, Cursor, or Copilot. It does not read their logs or trust their output.

```
Your AI agent          Vigil backend (local)
     │                        │
     │  writes files          │  watches file system
     │  spawns processes  ──► │  watches process table
     │  makes connections     │  watches network stack
     │                        │
     └──────── VS Code sidebar shows what actually happened
```

Everything runs on your machine. Zero cloud. Zero telemetry. Wireshark-verifiable.

---

## Supported agents

| Agent | Detected automatically |
|---|---|
| Claude Code | ✅ |
| Cursor | ✅ |
| GitHub Copilot | ✅ |
| Codex CLI | ✅ |

---

## MCP integration

Vigil exposes a local MCP server at `http://127.0.0.1:7422/mcp`. This lets Claude Code query Vigil directly during a session — asking what it has done so far, what files it touched, or whether any anomalies were detected.

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "vigil": {
      "type": "http",
      "url": "http://127.0.0.1:7422/mcp"
    }
  }
}
```

---

## Requirements

- Windows 10 or 11 (macOS coming)
- The Vigil backend installer — download from [getvvault.com](https://getvvault.com)
- VS Code 1.85 or later

---

## Installation

**Step 1 — Install the VS Code extension**

Search `Vigil AI Monitor` in the Extensions panel, or install directly:

```
ext install vvault.vigil-ai-monitor
```

**Step 2 — Download and run the Vigil backend**

The extension requires the Vigil tray app to run alongside VS Code. Download `Vigil-Setup.exe` from [getvvault.com](https://getvvault.com) and run the installer.

**Step 3 — Start the tray app before opening VS Code**

Launch Vigil from your Start menu. Wait for the tray icon to appear, then open VS Code. The Vigil sidebar will connect automatically.

---

## Session stats

Hover the status bar item (`Vigil: X.Xm`) to see a quick summary of the current session — agent, duration, files touched, friction signals, and Red Lines — without opening the sidebar.

![Session stats tooltip](https://download.getvvault.com/vigil_stats.png)

---

## What's new in 0.2.16

- Images now render correctly on the Marketplace
- Backend auto-start improved — handles stale processes and zombie detection
- Registry detection now reads the correct Windows startup key

[Full changelog](https://github.com/gbhide1993/vigil/blob/main/vigil-vscode/CHANGELOG.md)

---

## FAQ

**Does Vigil send any data to the cloud?**
No. Everything runs locally. The backend is a local process on your machine. No telemetry, no outbound connections, Wireshark-verifiable.

**Does Vigil work without the tray app?**
No. The VS Code extension is the sidebar UI. The tray app is the backend that does the actual OS-level monitoring. Both are required.

**Does it slow down my machine or the agent?**
No. Vigil is a passive observer. It does not instrument the agent, inject into processes, or intercept traffic. It watches at the OS level with negligible overhead.

**Does it work with multiple agents running at the same time?**
It detects which agent is active and tracks the current session. Multi-agent support is on the roadmap.

**The sidebar shows offline / empty. What do I do?**
Make sure the Vigil tray app is running before you open VS Code. Check the tray icon in the bottom-right system tray. If it is missing, launch Vigil from the Start menu and reload the VS Code window.

**Can I query Vigil from inside Claude Code?**
Yes, via MCP. See the MCP integration section above.

---

## Troubleshooting

**Red Lines section is empty**
The backend is running but no Red Line thresholds have been crossed. This is normal. Red Lines only fire on high-risk events.

**MCP shows `ConnectionRefused`**
The backend is not running or has not fully started yet. Check the Vigil tray icon. If missing, launch Vigil from Start menu, wait 10 seconds, then run `claude mcp list` again.

**Sidebar shows offline after install**
Start the Vigil tray app first, then reload the VS Code window with `Ctrl+Shift+P` → "Reload Window".

---

## Privacy

Vigil monitors your local machine. It does not transmit session data, file contents, network logs, or any other information externally. The local SQLite database at `%LOCALAPPDATA%\V-LAW\data\vlaw.db` stores session history on your machine only.

---

**getvvault.com · support@getvvault.com**
