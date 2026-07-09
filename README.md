# V-LAW — Local AI Agent Watchdog

![License](https://img.shields.io/badge/license-Proprietary-red)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Version](https://img.shields.io/badge/version-1.0.0--beta-orange)
![Downloads](https://img.shields.io/github/downloads/gbhide1993/vlaw/total)

Local OS-level monitor for Claude Code, Cursor, and Copilot.  
Tray icon goes red when agents access files, network, credentials, or spawn suspicious processes.  
**Zero cloud. Zero Docker. One-click Windows installer.**

---

## Download

### [https://github.com/gbhide1993/vlaw/releases/download/v0.1.1-beta/VLaw-Setup.exe]

Windows 10/11 · 101MB · One-click install

> Windows will show "Windows protected your PC" → click **More info** → **Run anyway**  
> (Unsigned beta — SHA256 in release notes to verify)

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
| Hidden cache writes | Claude Code's ~/.claude/file-history/ backup |

---

## How It Works

1. Install → tray icon appears within 10 seconds
2. Start your AI agent (Claude Code, Cursor, Copilot)
3. V-LAW detects it automatically
4. Tray goes **red** if something needs attention
5. Click tray → see what happened → Allow / Investigate / BLOCK

---

## Pricing

| Plan | Price | What's included |
|---|---|---|
| Individual | $9/month | 1 machine, all features, all agents |
| Annual | $99/year | Same, 2 months free |

**Beta is free.** Pricing activates after beta period.  
Early testers locked in at beta price permanently.

---

## Requirements

- Windows 10 or 11 (64-bit)
- At least one AI coding agent installed
- 200MB disk space

---

## Feedback

Found a bug? [Open an issue](https://github.com/gbhide1993/vlaw/issues)  
Have a question? [Start a discussion](https://github.com/gbhide1993/vlaw/discussions)  
Security issue? Email girish@getvvault.com

---

## License

Proprietary. See [LICENSE](LICENSE) for details.
