#!/usr/bin/env python3
"""
Standalone subprocess worker: checks which of a list of candidate PIDs
currently has a given file path open, and prints the result as JSON.

Exists to isolate psutil.Process.open_files() from the caller's process.
On Windows, the underlying C extension call (NtQuerySystemInformation /
DuplicateHandle / NtQueryObject) does NOT release the GIL -- confirmed by
reading psutil's own Windows C source -- and NtQueryObject specifically has
a well-documented Windows bug where querying a handle tied to a pending
synchronous I/O operation (e.g. a named pipe) can hang that thread
indefinitely. Since the GIL is held the whole time, that hang freezes the
*entire* calling process, not just the thread that made the call -- a
same-process ThreadPoolExecutor thread cannot be killed out from under
this; confirmed live via py-spy during a real multi-minute app freeze
where every worker in file_watcher.py's dedicated open-handle pool was
simultaneously stuck here.

Running this in a disposable subprocess sidesteps it entirely: the
subprocess has its own GIL, so a hang here never blocks the caller's event
loop, and the caller can hard-kill this process (proc.kill()) if it
doesn't finish in time -- exactly the same isolation
watchers.process_watcher._run_process_scan already relies on for its own
psutil calls.

Usage: python _open_handle_worker.py <path> <pid1,pid2,...>
Prints: {"matched_pid": <int or null>, "error": <str or null>}
"""
import json
import os
import sys

try:
    import psutil
except ImportError:
    print(json.dumps({"matched_pid": None, "error": "psutil not available"}))
    sys.exit(0)


def find_pid_with_open_handle(path: str, candidate_pids: list[int]) -> int | None:
    """Same matching semantics as the in-process version this replaces --
    returns the one PID that has `path` open, or None if zero or more than
    one candidate does (ambiguous -- caller falls back to its own
    first-match-low-confidence heuristic). Never raises for an individual
    candidate: a process that has since exited or denies access is just
    skipped, not reported."""
    normalized_target = os.path.normcase(os.path.abspath(path))
    found: list[int] = []
    for pid in candidate_pids:
        try:
            for f in psutil.Process(pid).open_files():
                if os.path.normcase(os.path.abspath(f.path)) == normalized_target:
                    found.append(pid)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return found[0] if len(found) == 1 else None


def main(args=None):
    """`args` defaults to sys.argv[1:] for standalone script invocation
    (dev mode). When called as a plain function from main.py's frozen-mode
    sentinel dispatch, the caller passes sys.argv[2:] explicitly instead --
    see main.py's comment for why argv[1] itself can't be used there."""
    if args is None:
        args = sys.argv[1:]

    if len(args) < 2:
        print(json.dumps({"matched_pid": None, "error": "usage: <path> <pid1,pid2,...>"}))
        return

    path = args[0]
    try:
        candidate_pids = [int(p) for p in args[1].split(",") if p.strip()]
    except ValueError as e:
        print(json.dumps({"matched_pid": None, "error": f"bad pid list: {e}"}))
        return

    try:
        matched = find_pid_with_open_handle(path, candidate_pids)
        print(json.dumps({"matched_pid": matched, "error": None}))
    except Exception as e:
        print(json.dumps({"matched_pid": None, "error": str(e)}))


if __name__ == "__main__":
    main()
