#!/usr/bin/env python3
"""
Standalone subprocess worker: scans all OS processes and prints a JSON snapshot.
Runs with its own GIL — if it hangs, the parent kills the subprocess without
affecting the main event loop.

Optionally accepts a comma-separated list of agent-related PIDs as argv[1] —
for exactly those PIDs (already narrowed down by the caller's name-filter,
never "every process"), this worker also collects environ()/cmdline()/exe(),
so those calls happen in this disposable process too, not the caller's.

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
            envs[pid] = proc.environ()
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


def main():
    agent_pids = set()
    if len(sys.argv) > 1:
        try:
            agent_pids = {int(p) for p in sys.argv[1].split(',') if p.strip()}
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
