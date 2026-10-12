"""Nothing outside main.py may import main (in the exe, main.py runs as
__main__ and `import main` loads a second copy with its own empty state), and
scope add / remove must reach the real file observer when main runs as
__main__, exactly as in the PyInstaller exe. See conftest.py for why
VLAW_DATA_DIR is set there rather than here."""

import ast
import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
SKIP_DIRS = {"tests", ".venv", "build", "dist", "__pycache__", "data", "node_modules"}


def _backend_modules():
    for path in BACKEND.rglob("*.py"):
        parts = set(path.relative_to(BACKEND).parts[:-1])
        if parts & SKIP_DIRS or any(p.startswith("data") or p.startswith(".") for p in parts):
            continue
        yield path


def test_no_module_other_than_main_imports_main():
    offenders = []
    for path in _backend_modules():
        if path.name == "main.py" and path.parent == BACKEND:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name == "main" or a.name.startswith("main.") for a in node.names):
                offenders.append(f"{path.relative_to(BACKEND)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module and (
                node.module == "main" or node.module.startswith("main.")
            ):
                offenders.append(f"{path.relative_to(BACKEND)}:{node.lineno}")
    assert offenders == [], f"modules importing main (loads a second copy in the exe): {offenders}"


def test_routes_use_the_shared_runtime_state_module():
    import core.runtime_state as runtime_state
    import main as main_module

    assert main_module._state is runtime_state.state
    assert main_module._stats_cache is runtime_state.stats_cache


def test_logging_setup_is_idempotent_for_the_same_file(tmp_path):
    from logging.handlers import RotatingFileHandler

    from core.log_setup import configure_logging

    root = logging.getLogger()
    before = list(root.handlers)
    log_file = str(tmp_path / "twice.log")
    try:
        configure_logging(log_file, "INFO")
        configure_logging(log_file, "INFO")     # a second copy of main.py would do this
        mine = [h for h in root.handlers if isinstance(h, RotatingFileHandler) and h.baseFilename == log_file]
        assert len(mine) == 1
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)
                h.close()


# ------------------------------------------- main running as __main__ (the exe)

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _call(port, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _kill_tree(proc):
    import psutil

    try:
        root = psutil.Process(proc.pid)
        children = root.children(recursive=True)
    except psutil.NoSuchProcess:
        return
    for p in children + [root]:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass
    proc.wait(timeout=20)


def test_scope_add_and_remove_reach_the_observer_when_main_runs_as___main__(tmp_path):
    """Starts `python main.py` (main as __main__, as in the PyInstaller exe) with an
    isolated data directory on a free port, then adds and removes a folder through
    the real API and checks what the live observer is watching."""
    port = _free_port()
    log_file = tmp_path / "backend.log"
    local = tmp_path / "localappdata"
    local.mkdir()
    project = tmp_path / "my project"
    project.mkdir()
    env = {
        **os.environ,
        "VLAW_DATA_DIR": str(tmp_path / "data"),
        "VLAW_POLICY_FILE": str(tmp_path / "policy" / "vlaw-policy.json"),
        "VLAW_LICENSE_FILE": str(tmp_path / ".vlaw-license"),
        "VLAW_PORT": str(port),
        "VLAW_LOG_FILE": str(log_file),
        "LOCALAPPDATA": str(local),
    }
    stdout = open(tmp_path / "stdout.txt", "wb")
    proc = subprocess.Popen([sys.executable, "main.py"], cwd=str(BACKEND), env=env, stdout=stdout, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 120
        up = False
        while time.time() < deadline and proc.poll() is None:
            try:
                status, _ = _call(port, "GET", "/api/health")
                if status == 200:
                    up = True
                    break
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            time.sleep(0.5)
        assert up, f"backend did not start: {(tmp_path / 'stdout.txt').read_text(errors='replace')[-1500:]}"

        status, before = _call(port, "GET", "/api/scope")
        # An elevated machine (a CI runner as Administrator) starts the ETW tier instead of the folder
        # observer. ETW sees every recognised agent's changes without a folder list, so there the live
        # apply is reported as applied and observed_paths stays empty; the folder tier lists the path.
        assert status == 200 and before["file_watcher_tier"] in ("folders", "etw")
        folder_tier = before["file_watcher_tier"] == "folders"
        stored = Path(project).resolve().as_posix()
        assert stored.lower() not in [p.replace("\\", "/").lower() for p in before["observed_paths"]]

        status, added = _call(port, "POST", "/api/scope", {"path": str(project)})
        assert status == 200, added
        assert added["applied_live"] is True and added["message"] is None
        status, during = _call(port, "GET", "/api/scope")
        if folder_tier:
            assert stored.lower() in [p.replace("\\", "/").lower() for p in during["observed_paths"]], \
                "the added folder must be on the running observer, with no restart"
        else:
            assert during["observed_paths"] == []
        assert [f["path"].lower() for f in during["folders"]] == [stored.lower()], "the folder is saved either way"

        status, removed = _call(port, "DELETE", "/api/scope", {"path": str(project)})
        assert status == 200, removed
        assert removed["applied_live"] is True
        status, after = _call(port, "GET", "/api/scope")
        assert stored.lower() not in [p.replace("\\", "/").lower() for p in after["observed_paths"]]
        assert after["folders"] == []

        text = log_file.read_text(encoding="utf-8", errors="replace")
        assert text.count("V-LAW backend starting") == 1, "main must not run a second time (a second copy of main was imported)"
        lines = [line for line in text.splitlines() if "ProcessWatcher" in line or "scheduler started" in line]
        assert len(lines) == len(set(lines)) or all(lines.count(l) == 1 for l in set(lines) if "scheduler started" in l)
    finally:
        _kill_tree(proc)
        stdout.close()
