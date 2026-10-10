#!/usr/bin/env python3
"""
Standalone subprocess worker: scans all OS processes and prints a JSON snapshot.
Runs with its own GIL — if it hangs, the parent kills the subprocess without
affecting the main event loop.

Optionally accepts a comma-separated list of agent-related PIDs as argv[1] —
for exactly those PIDs (already narrowed down by the caller's name-filter,
never "every process"), this worker also collects environ()/cmdline()/exe(),
so those calls happen in this disposable process too, not the caller's.
environ() is reduced to the few variables RL7 needs before anything is
printed (see _filter_env): other values never leave this process.

Process enumeration itself prefers a single Get-CimInstance Win32_Process
WMI query (see _enum_processes_powershell) over psutil.process_iter
(per-process OpenProcess calls, ~13-15s measured on a real dev machine —
wmic.exe itself was tried first but is absent on this machine, as Microsoft
has been removing it from newer Windows 11 builds). Falls back to
psutil.process_iter if the PowerShell query fails or returns nothing.
"""
import csv
import io
import json
import re
import subprocess
import sys

try:
    import psutil
except ImportError:
    print(json.dumps({"error": "psutil not available", "processes": [], "envs": {}, "cmdlines": {}}))
    sys.exit(0)


def _enum_processes_powershell():
    """Fast Windows process enumeration via Get-CimInstance. Single WMI
    query, confirmed working on this machine — wmic.exe itself is absent
    (Microsoft has been removing it from newer Windows 11 builds), which is
    why this uses Get-CimInstance instead."""
    try:
        result = subprocess.run(
            [
                'powershell', '-NoProfile', '-NonInteractive', '-Command',
                'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Csv -NoTypeInformation'
            ],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        processes = []
        reader = csv.DictReader(io.StringIO(result.stdout))
        for row in reader:
            try:
                pid = int(row.get('ProcessId', '').strip().strip('"'))
                ppid = int(row.get('ParentProcessId', '0').strip().strip('"') or '0')
                name = (row.get('Name') or '').strip().strip('"').lower()
                if pid and name:
                    processes.append({
                        'pid': pid,
                        'name': name,
                        'ppid': ppid,
                        'status': 'running',
                    })
            except (ValueError, KeyError):
                continue
        return processes
    except Exception:
        return []  # caller handles empty list


def _enum_processes_psutil():
    """Fallback full-process enumeration — used only if wmic is unavailable
    or returned nothing. Same per-process OpenProcess cost this worker
    exists to isolate from the parent process's event loop in the first
    place; still cheaper here (disposable subprocess, killable) than in the
    parent even at its slower, ~13s-on-this-machine pace."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'status']):
        try:
            info = proc.info
            pid = info.get('pid')
            if pid is None:
                continue
            processes.append({
                'pid': pid,
                'name': (info.get('name') or '').lower(),
                'ppid': info.get('ppid') or 0,
                'status': info.get('status') or '',
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return processes


# Environment variables the backend's RL7 check (core/red_lines.py) and the
# correlation engine's "LLM API key in env" signal need. Mirrors
# watchers/process_watcher.py::RELEVANT_ENV_VARS (kept in sync by a test);
# duplicated here because this file also runs as a standalone script with
# no package context. Everything else in a process's environment is dropped
# in this worker and never crosses the process boundary.
_URL_ENV_VARS = {"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL"}
_KEY_ENV_VARS = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}

_URL_USERINFO = re.compile(r"^([A-Za-z][\w+.\-]*://)[^/@\s]*@")


def _sanitize_url(value: str) -> str:
    """Keeps what the redirect check needs (scheme, host, port, path) and
    drops credentials embedded in the URL (user:pass@) plus any query or
    fragment, where tokens commonly end up."""
    value = _URL_USERINFO.sub(r"\1", value)
    for sep in ("?", "#"):
        value = value.split(sep, 1)[0]
    return value


def _filter_env(env: dict) -> dict:
    """Reduces a full process environment to what RL7 needs: *_BASE_URL
    values (sanitized), and for *_API_KEY variables only True (present).
    API key values are never returned, not even hashed: nothing consumes
    them and a fingerprint would still let a stolen log confirm a guess."""
    out = {}
    for name, value in env.items():
        upper = name.upper()
        if upper in _URL_ENV_VARS:
            out[upper] = _sanitize_url(value) if isinstance(value, str) else ""
        elif upper in _KEY_ENV_VARS:
            out[upper] = bool(value)
    return out


def _gather_envs_and_cmdlines(agent_pids: set[int]) -> tuple[dict, dict]:
    """environ()/cmdline()/exe() for agent_pids only (typically 0-5
    processes) — decoupled from process enumeration above so it runs the
    same way regardless of which enumeration path produced `processes`."""
    envs = {}
    cmdlines = {}
    for pid in agent_pids:
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            envs[pid] = {}
            cmdlines[pid] = {"args": [], "exe_path": ""}
            continue

        try:
            envs[pid] = _filter_env(proc.environ())
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            envs[pid] = {}
        try:
            args = proc.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            args = []
        try:
            exe_path = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            exe_path = ""
        cmdlines[pid] = {"args": args, "exe_path": exe_path}
    return envs, cmdlines


def main(args=None):
    """`args` defaults to sys.argv[1:] for standalone script invocation
    (dev mode: [sys.executable, _WORKER_PATH, "<pids>"]). When called as a
    plain function from main.py's frozen-mode sentinel dispatch, the
    caller passes sys.argv[2:] explicitly instead -- the process's real
    argv there is [exe, "--process-scan-worker", "<pids>"], so sys.argv[1]
    itself is the sentinel, not the pid list, and reading it directly here
    would silently parse the sentinel string as pids, fail, and always
    fall back to an empty agent_pids (a real bug this signature avoids)."""
    if args is None:
        args = sys.argv[1:]

    agent_pids = set()
    if args:
        try:
            agent_pids = {int(p) for p in args[0].split(',') if p.strip()}
        except ValueError:
            pass

    try:
        processes = _enum_processes_powershell()
        if not processes:
            processes = _enum_processes_psutil()
    except Exception as e:
        print(json.dumps({"error": str(e), "processes": [], "envs": {}, "cmdlines": {}}))
        sys.exit(0)

    try:
        envs, cmdlines = _gather_envs_and_cmdlines(agent_pids)
    except Exception as e:
        print(json.dumps({"error": str(e), "processes": processes, "envs": {}, "cmdlines": {}}))
        sys.exit(0)

    print(json.dumps({"error": None, "processes": processes, "envs": envs, "cmdlines": cmdlines}))


if __name__ == '__main__':
    main()
