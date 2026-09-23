"""Runs the V-LAW backend natively on Windows, bypassing Docker entirely.

Docker Desktop's WSL2 backend doesn't reliably expose the Windows host
filesystem at /host on this machine (see README "Platform notes"), so
the file watcher never sees real host paths when run in a container.
Running natively sidesteps that: watchers operate directly on real
Windows paths, no bind mount involved.

Uses its own policy file (vlaw-policy.native.json) with real Windows
paths instead of the container-oriented defaults in vlaw-policy.json,
and VLAW_HOST_ROOT is left unset so paths resolve as-is.
"""

import os

import sys
if sys.platform == 'win32':
    import asyncio
    asyncio.set_event_loop_policy(
        asyncio.WindowsSelectorEventLoopPolicy()
    )

# Absolute and LOCALAPPDATA-anchored, not relative to cwd -- "../data"
# only resolved correctly when launched with cwd=backend/; launched from
# anywhere else (e.g. cwd=repo root) it silently wrote the DB outside the
# repo entirely (e.g. C:\Users\<user>\data\vlaw.db). Matches the frozen
# build's own DB location (main.py's get_base_path), so native runs and
# the installed .exe share the same on-disk DB.
_local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
os.environ.setdefault("VLAW_DATA_DIR", os.path.join(_local_app_data, "V-LAW", "data"))
os.environ.setdefault("VLAW_POLICY_FILE", "../policy/vlaw-policy.native.json")
os.environ.setdefault("VLAW_PORT", "7422")
# Deliberately no VLAW_HOST_ROOT — native paths need no /host prefix.

import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ["VLAW_PORT"]), reload=False)
