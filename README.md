# V-LAW — Local AI Agent Watchdog

![License](https://img.shields.io/badge/license-Proprietary-red)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-0.2.0--beta-orange)

<img width="3189" height="1671" alt="vlaw_arch" src="https://github.com/user-attachments/assets/83aae026-707c-4f17-86a4-dfdd6b20048a" />


Local OS-level monitor for Claude Code, Cursor, and Copilot.
Tray icon goes red when agents access files, network, credentials, or spawn suspicious processes.
**Zero cloud. Zero Docker. One-click Windows installer.**

---

## Download

### [⬇ Download VLaw-Setup.exe — v0.2.0-beta](https://github.com/gbhide1993/vlaw/releases/download/v0.2.0-beta/VLaw-Setup.exe)

Windows 10/11 · 103MB · One-click install

> Windows will show "Windows protected your PC" → click **More info** → **Run anyway**
> (Unsigned beta — SHA256 below to verify)

**SHA256:**
5EBA33155F05EEB7F2B1AF459A84B6B206D5C0A8A72156E337E138451184200B

Verify:
```powershell
Get-FileHash VLaw-Setup.exe -Algorithm SHA256
```

---

## Quick check (no install needed)

See what Claude Code has been storing on your machine:

```bash
npx check-claude-history
```

---

## What It Watches

| Activity | What V-LAW catches |
|---|---|
| File access | Every read and write per agent, per session |
| Network connections | Flags unknown destinations |
| Process spawns | Flags curl, wget, ssh, and dangerous commands |
| Credential access | .env, .ssh, .aws — instant HIGH alert |
| Hidden cache writes | Claude Code's ~/.claude/file-history/ backup, with checkpoint-activity correlation to reduce false positives |
| Environment redirects | Detects CVE-2026-21852 pattern — ANTHROPIC_BASE_URL manipulation |
| Malicious config execution | Detects CVE-2025-59536 pattern — code execution before trust dialog |
| MCP auto-approval | Detects untrusted MCP servers auto-approved from new projects |
| Cross-agent conflicts | Two different agents touching the same file, or credentials accessed by multiple agents |
| Agent honesty | Session Verification Report — compares OS-observed activity against the agent's own self-reported logs |
| Known CVEs | Checks your installed Claude Code version against disclosed vulnerabilities |
| Native config gaps | Config Auditor — checks your Claude Code permissions against recommended protections |

---

## How It Works

1. Install → tray icon appears within 10 seconds
2. Start your AI agent (Claude Code, Cursor, Copilot)
3. V-LAW detects it automatically
4. Tray goes **red** if something needs attention
5. Click tray → see what happened → Allow / Investigate / BLOCK
6. Every morning at 9AM, a digest tells you what's been happening — even on clean days

---

## What's New in v0.2.0-beta

- **Session Verification Report** — independently verifies whether your AI agent's own activity log matches what actually happened at the OS level
- **CVE detection** — flags patterns matching CVE-2025-59536 and CVE-2026-21852, plus a version checker against known vulnerabilities
- **Cross-agent correlation** — the one thing no other local monitoring tool does: sees when multiple agents touch the same resource
- **Config Auditor** — tells you exactly which native Claude Code permission rules you're missing, with a one-click "Fix this" breakdown
- **Daily proof-of-value digest** — days clean, files monitored, destinations verified, shown even when nothing went wrong
- **Critical reliability fixes** — resolved a backend freeze under load and a duplicate-process bug on launch

Full changelog: [CHANGELOG.md](CHANGELOG.md)

---

## Requirements

- Windows 10 or 11 (64-bit)
- At least one AI coding agent installed (Claude Code, Cursor, or Copilot)
- 200MB disk space

---

## Pricing

| Plan | Price | What's included |
|---|---|---|
| Individual | $9/month | 1 machine, all features, all agents |
| Annual | $99/year | Same, 2 months free |

**Beta is free.** Pricing activates after beta period.
Early testers locked in at beta price permanently.

---

## Feedback

Found a bug? [Open an issue](https://github.com/gbhide1993/vlaw/issues)
Have a question? [Start a discussion](https://github.com/gbhide1993/vlaw/discussions)
Security issue? See [SECURITY.md](SECURITY.md) or email girish@getvvault.com

---

## License

Proprietary. See [LICENSE](LICENSE) for details.
