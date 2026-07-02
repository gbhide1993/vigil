# V-LAW — Vvault Local AI Watchdog

Locally deployed watchdog service that monitors cloud AI agents (Cursor,
Claude Code, GitHub Copilot, Salesforce Agentforce) operating inside a
company's local perimeter. Watches file system access, network
connections, process activity, and credential file access per agent.
Attributes every action to the correct agent. Logs everything locally
in SQLite. Zero data leaves the machine.

## Quick start

```bash
cp .env.example .env
docker compose up --build
```

- Backend API: http://localhost:7422
- Frontend: http://localhost:7423

## Local development (without Docker)

Backend:

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate  # or source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
VLAW_DATA_DIR=../data VLAW_POLICY_FILE=../policy/vlaw-policy.json uvicorn main:app --port 7422
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

## Native Windows mode (backend only)

If Docker Desktop's host filesystem mount isn't visible inside the
container on your machine (see "Platform notes" below), run the
backend directly on Windows instead — no container, no `/host` mount,
watchers operate on real Windows paths:

```bat
start_native.bat
```

This installs backend dependencies and runs
[backend/run_native.py](backend/run_native.py), which uses
[policy/vlaw-policy.native.json](policy/vlaw-policy.native.json) — a
policy file with real Windows paths (`C:\Users\...`) instead of the
container-oriented defaults in `vlaw-policy.json`. Customize
`scope_directories` and `credential_paths` in that file for your setup.
Out of the box it watches `C:\Users\<you>\vlaw\policy` as a test
directory, plus `.ssh`/`.aws` under your user profile for credentials
— **avoid pointing `scope_directories` at your whole home directory**;
`PollingObserver` walks the entire tree on every poll, so a directory
with hundreds of thousands of files (AppData, node_modules, browser
caches, etc.) will peg a CPU core and never finish starting. Point it
at specific project or credential folders instead.

Keep the frontend in Docker, pointed at the native backend via
`host.docker.internal`:

```bash
docker compose -f docker-compose.yml -f docker-compose.native.yml up vlaw-frontend
```

(Compose still creates the `vlaw` backend container due to
`depends_on` — stop it with `docker compose stop vlaw` since the
native process is serving port 7422 instead.)

## Architecture

- **backend/watchers/** — file, process, network, and MCP watchers.
  File watching uses `watchdog.PollingObserver` (not native OS events)
  so it works reliably under Docker Desktop on Windows.
- **backend/core/** — aggregation (windowed event collapsing),
  attribution (mapping OS signals to agents), alerting, and the Layer 1
  statistical baseline.
- **backend/db/** — SQLite schema and connection management.
- **backend/license/** — offline RSA-2048 signed license validation,
  14-day trial fallback.
- **policy/vlaw-policy.json** — the Frank Besadesky control model:
  approved agents, scope directories, credential paths, MCP servers.

## Platform notes

- **Docker Desktop on Windows (WSL2 backend):** the `/:/host:ro` mount in
  `docker-compose.yml` exposes the WSL2 VM's root filesystem, not the
  Windows `C:` drive directly. If `scope_directories` in
  `vlaw-policy.json` don't show up under the container's `/host`, open
  Docker Desktop → Settings → Resources → File sharing and confirm the
  drives containing your `scope_directories` are shared, then verify
  with `docker compose exec vlaw ls /host/host_mnt`. This is a Docker
  Desktop/WSL2 configuration detail, independent of V-LAW's watcher
  logic (which uses `PollingObserver` specifically so it keeps working
  once the mount is visible).
- `scope_directories` and `credential_paths` in the policy file are
  defined from the host's perspective; V-LAW automatically prefixes
  them with `VLAW_HOST_ROOT` (set to `/host` in `docker-compose.yml`)
  before watching.

## Constraints

- Zero data leaves the machine — no telemetry, no license phone-home.
- SQLite only, single file, zero external server dependency.
- Host filesystem mount is read-only.
- Trial mode works without any license file: 14 days, 1 agent, 24h
  retention window.
