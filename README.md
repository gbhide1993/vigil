# Vigil — Dashcam for AI Coding Agents

![Version](https://img.shields.io/badge/version-0.2.1--beta-orange)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)

**Observe everything. Interrupt almost never.**

Vigil is a local black box recorder for AI coding agents. It quietly watches what Claude Code, Cursor, and Copilot actually do on your machine — at the OS level, independent of what any agent reports about itself. Sits in your system tray. Says nothing unless something deserves your attention.

---

## Download

### [⬇ Download VLaw-Setup.exe — v0.2.1-beta](https://github.com/gbhide1993/vlaw/releases/download/v0.2.1-beta/VLaw-Setup.exe)

Windows 10/11 · 116MB · One-click install · No Docker · No Python

> Windows will show "Windows protected your PC" → click **More info** → **Run anyway**
> Unsigned beta. Verify with SHA256 below.

**SHA256:**
5EBA33155F05EEB7F2B1AF459A84B6B206D5C0A8A72156E337E138451184200B

Verify:
```powershell
Get-FileHash VLaw-Setup.exe -Algorithm SHA256
```

---

## Quick check — no install needed

See what Claude Code has been storing on your machine:

```bash
npx check-claude-history
```

---

## How it works

Install → tray icon appears. Green means quiet. You forget it's there.

One day: *"Hey, Claude just tried reading ~/.ssh"*

That's the moment. Everything before it was the dashcam rolling in the background.

Three modes:
- 🟢 **Quiet** — everything normal, nothing to see
- 🟡 **FYI** — morning digest, interesting observations, nothing urgent  
- 🔴 **Incident** — something happened, full story, evidence, export

---

## What it watches

| What | How |
|---|---|
| File reads and writes | OS-level, per agent, per session |
| Network connections | Every socket, every destination, flagged if unknown |
| Process spawns | Every command, flagged if dangerous (curl, wget, ssh) |
| Credential file access | .env, .ssh, .aws — instant alert, no exceptions |
| MCP server connections | Auto-detected, flagged if untrusted and auto-approved |
| Cross-agent conflicts | Two agents touching the same file with no commit between |
| Agent self-report vs OS truth | Session Verification Report — catches what agents don't log |
| Known CVEs | CVE-2025-59536, CVE-2026-21852 — version-checked |
| Native config gaps | Config Auditor — shows exactly what protections are missing |

---

## Eight Red Line rules (non-disableable)

These fire regardless of any configuration. Cannot be dismissed without review.

| Rule | What triggers it |
|---|---|
| RL1 | Any agent reads your SSH directory |
| RL2 | Any agent reads .env files outside the active project |
| RL3 | Hidden cache writes with no active session (checkpoint-aware) |
| RL4 | Network call to an unknown destination |
| RL5 | Agent spawns curl, wget, nc, or ssh |
| RL6 | Agent reads files from a different client project |
| RL7 | ANTHROPIC_BASE_URL redirect detected (CVE-2026-21852 pattern) |
| RL8 | Untrusted MCP server auto-approved from a new project |

---

## What makes it different

Every other local AI agent monitor reads the agent's own session logs.

Vigil watches at the OS level. If an agent's traffic is silently redirected, or its logging is incomplete, the agent's own log won't show it. Vigil's OS-level observation will.

| Capability | Native agents | agentwatch / ai-observer | Vigil |
|---|---|---|---|
| Audit logging without enterprise plan | No | Yes | Yes |
| Cross-agent visibility | No | Yes (per-adapter) | Unified event store |
| OS truth vs agent self-report | No | No — reads agent logs | Yes — unique |
| Cross-agent file conflict detection | No | No | Yes — unique |
| Named CVE detection | No | No | 2 verified CVEs |
| Native config gap auditor | No | No | Yes — unique |
| Zero-config install | N/A | Requires toolchain | One-click .exe |

---

## Pricing

Beta is free. Pricing activates after beta period. Early subscribers locked in permanently.

| Plan | Price |
|---|---|
| Individual | $9/month or $99/year |
| Team | $19/node/month |

→ [Subscribe on Polar.sh](https://polar.sh/gbhide1993/products/vigil)

---

## Honest scope

- Windows only — macOS port not yet built
- Watches Claude Code, Cursor, and Copilot — not every AI agent
- CVE tracking covers Claude Code only so far
- Cross-agent correlation has no git-commit awareness yet
- Installer is unsigned (SmartScreen warning on install)

---

## Requirements

- Windows 10 or 11 (64-bit)
- At least one of: Claude Code, Cursor, or GitHub Copilot installed

---

## Feedback and issues

Found a bug → [Open an issue](https://github.com/gbhide1993/vlaw/issues)

Question → [Start a discussion](https://github.com/gbhide1993/vlaw/discussions)

Security issue → girish@getvvault.com

---

## License

Proprietary. See [LICENSE](LICENSE) for terms.
