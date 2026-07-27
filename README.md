# Vigil — Black Box for AI-Assisted Software Development

![Version](https://img.shields.io/badge/version-0.2.1--beta-orange)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)

> **Observe everything. Interrupt almost never.**

Vigil is an independent evidence platform for AI-assisted software development.

It continuously observes what AI coding agents actually do on your machine, reconstructs complete engineering sessions, and provides trustworthy evidence when something matters.

Unlike agent-native audit logs, Vigil records **what the operating system observed**, not what an AI agent chose to report.

---

## Why Vigil Exists

AI coding agents are quickly becoming part of everyday software engineering.

They write code.

They execute commands.

They modify files.

They access credentials.

They connect to external services.

When something goes wrong, engineering teams need answers such as:

- What actually happened?
- Which AI agent changed this?
- Can I trust the agent's own logs?
- What happened before production changed?
- What files and credentials were accessed?

Most existing tools rely on **agent-emitted telemetry or self-reported session logs.**

Vigil doesn't.

It independently records OS-level evidence, reconstructs complete engineering sessions, and preserves trustworthy evidence for investigation.

---

# Built For

Vigil is designed for teams adopting AI-assisted software development.

Ideal users include:

- CTOs
- VP Engineering
- Platform Engineering
- Engineering Managers
- Security Engineering
- Developer Productivity teams

---

# What Vigil Does

## Observe

Continuously records independent OS-level evidence.

- File reads & writes
- Process execution
- Terminal activity
- Network connections
- MCP server activity

---

## Reconstruct

Turns raw events into complete engineering stories.

- Session timelines
- Cross-agent activity
- Incident replay
- Historical evidence

---

## Verify

Compares AI self-reporting with independent OS evidence.

- Session Verification Reports
- Config Auditor
- CVE detection
- Red Line Rules

---

# Three Operating Modes

Most of the time, Vigil stays completely out of your way.

### 🟢 Quiet

Everything looks normal.

Nothing needs your attention.

---

### 🟡 FYI

Interesting observations worth reviewing later.

Morning digest.

Configuration suggestions.

Non-urgent events.

---

### 🔴 Incident

Something important happened.

Vigil reconstructs the complete story and provides exportable evidence.

---

# Questions Vigil Answers

| Engineering Question | Vigil |
|----------------------|--------|
| What actually happened? | Complete reconstructed timeline |
| Can I trust the AI agent's own logs? | Session Verification Report |
| Which AI agent modified this project? | Cross-agent correlation |
| What happened before deployment? | Historical evidence |
| Which protections are missing? | Config Auditor |
| Why did production change? | Investigation timeline |

---

# What Vigil Watches

| Category | Coverage |
|-----------|----------|
| File reads & writes | OS-level, per agent, per session |
| Network connections | Every destination, flagged if unknown |
| Process execution | Commands, shells, child processes |
| Credential access | `.env`, `.ssh`, `.aws`, certificates |
| MCP servers | Trusted / untrusted detection |
| Cross-agent conflicts | Multiple agents touching same files |
| AI self-report vs OS evidence | Session Verification |
| Known AI-agent CVEs | Version-aware detection |
| Native configuration gaps | Config Auditor |

---

# Eight Red Line Rules

These rules always execute.

They cannot be disabled.

| Rule | Trigger |
|------|----------|
| RL1 | AI agent reads SSH keys |
| RL2 | AI agent reads `.env` outside project |
| RL3 | Hidden cache writes without active session |
| RL4 | Network connection to unknown destination |
| RL5 | Agent launches `curl`, `wget`, `ssh`, or `nc` |
| RL6 | Reads files from another client project |
| RL7 | `ANTHROPIC_BASE_URL` redirect detected |
| RL8 | Untrusted MCP server auto-approved |

---

# Session Verification

Every AI coding tool ultimately reports its own activity.

Vigil independently records what the operating system observed.

When the two differ, Vigil generates a **Session Verification Report** highlighting discrepancies between agent-reported activity and OS-level evidence.

Evidence remains independent of the AI agent.

---

# Why Vigil Is Different

| Capability | Native Agent Logs | Origin | New Relic AI Coding Observability | Vigil |
|-------------|-------------------|---------|-----------------------------------|--------|
| Independent evidence | ❌ | ❌ | ❌ | ✅ |
| OS-level observation | ❌ | ❌ | ❌ | ✅ |
| Session reconstruction | Limited | Partial | Partial | ✅ |
| Cross-agent visibility | ❌ | Partial | Yes | ✅ |
| Verification of AI reports | ❌ | ❌ | ❌ | ✅ |
| Config auditing | Limited | ❌ | ❌ | ✅ |
| Named AI-agent CVE detection | ❌ | ❌ | ❌ | ✅ |
| Standalone install | N/A | CLI | Requires observability stack | ✅ |

---

# Investigation First

Vigil isn't designed to generate more alerts.

It's designed to answer difficult engineering questions.

When something unusual happens, Vigil reconstructs the complete engineering story.

```
Agent started
        ↓
Files accessed
        ↓
Commands executed
        ↓
Network connections
        ↓
Configuration changes
        ↓
Timeline reconstructed
        ↓
Exportable evidence
```

The goal isn't more telemetry.

The goal is understanding.

---

# Download

### ⬇ Download VLaw-Setup.exe (v0.2.1-beta)

https://github.com/gbhide1993/vlaw/releases/download/v0.2.1-beta/VLaw-Setup.exe

Windows 10 / 11

One-click installer

No Docker

No Python

Unsigned beta build.

Verify SHA256 before running.

```
SHA256

5EBA33155F05EEB7F2B1AF459A84B6B206D5C0A8A72156E337E138451184200B
```

PowerShell:

```powershell
Get-FileHash VLaw-Setup.exe -Algorithm SHA256
```

---

# Quick Check

Want to see what Claude Code has stored on your machine without installing Vigil?

```bash
npx check-claude-history
```

---

# Pricing

Beta is currently free.

Early subscribers keep their pricing permanently.

| Plan | Price |
|------|------:|
| Individual | $9/month or $99/year |
| Team | $19/node/month |

👉 https://polar.sh/gbhide1993/products/vigil

---

# Current Scope

Current beta focuses on:

- Windows
- Claude Code
- Cursor
- GitHub Copilot

Current limitations:

- Windows only
- macOS support planned
- Claude Code CVE detection only
- Installer currently unsigned

---

# Feedback

Issues:

https://github.com/gbhide1993/vlaw/issues

Discussions:

https://github.com/gbhide1993/vlaw/discussions

Security:

girish@getvvault.com

---

# Philosophy

Facts first.

Interpretation second.

Operating system evidence is the source of truth.

AI can summarize evidence.

AI should never become the evidence.

---

**Observe everything. Interrupt almost never.**
