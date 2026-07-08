# V-LAW — Local AI Agent Watchdog

Monitors what AI coding agents actually do on your machine.
Claude Code, Cursor, Copilot — file access, network connections,
process spawns, credential access. Real-time alerts. One-click install.

Zero cloud. Zero Docker. Everything stays on your machine.

---

## Download

[VLaw-Setup.exe — v1.0.0 Beta](https://github.com/gbhide1993/vlaw/releases/tag/v1.0.0-beta)

Windows 10/11 only.

> SmartScreen will show "Windows protected your PC" — click **More info** → **Run anyway**.  
> This appears because V-LAW is not yet code-signed.

SHA256: `EC1FA292B206641F7FAEF0808F827274A7CF7E9A1FEE3CC90F29C166006A2003`

---

## What It Watches

- File reads and writes per agent
- Network connections — flags unknown destinations
- Process and command spawns — flags curl, wget, ssh
- Credential file access — .ssh, .env, .aws
- MCP tool calls

---

## How It Works

One-click install. Tray icon sits quietly in green when all is clear.
Goes red when something needs your attention.
Click the tray to see what happened and block if needed.

No Docker. No terminal. No config files to edit.

---

## Requirements

- Windows 10 or 11 (64-bit)
- At least one AI coding agent (Claude Code, Cursor, or Copilot)
- 200MB disk space

---

## License

Proprietary. See [LICENSE](LICENSE) for details.

## Contact

girish@getvvault.com
