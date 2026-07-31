# Vigil — AI Session Monitor

See what Claude Code, Cursor, and Copilot actually do on your machine.

Vigil is an OS-level evidence platform that observes AI coding agent sessions. This extension surfaces that evidence directly inside VS Code — status bar state, sidebar views, file badges, and Red Line alerts — all backed by a local Vigil backend running on `localhost:7422`.

## What it shows

- **Status bar** — current session state at a glance: offline, ready, active (clean or with friction), or an active Red Line alert. Click it to open the Vigil dashboard.
- **Sidebar** (activity bar eye icon) — three views:
  - **Current Session** — agent, duration, status, files touched, friction signals, Red Lines.
  - **Red Lines** — Red Line events from the last 24 hours, with process and file context.
  - **Findings** — friction findings (e.g. retry loops) with confidence and file context.
- **File badges** — files with friction signals get a badge in the Explorer showing the friction count.
- **Red Line alerts** — a warning notification pops up the moment a new Red Line event is detected, with a link to view evidence.

## Requirements

- Vigil v0.2.1+ — installs automatically on first use if not already present.
- VS Code 1.85+.

## Settings

| Setting | Default | Description |
|---|---|---|
| `vigil.apiPort` | `7422` | Port where Vigil is running |
| `vigil.pollIntervalSeconds` | `10` | How often to poll Vigil (seconds) |
| `vigil.showFileDecorations` | `true` | Show friction badges on files in Explorer |
| `vigil.redLineNotifications` | `true` | Show notifications for Red Line events |

## Privacy

Everything stays on your machine. The extension reads from `localhost` only. Nothing is sent anywhere.
