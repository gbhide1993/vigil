"""The API has no authentication and mutating routes, so nothing may bind it to all interfaces by default.

Every uvicorn.run call and every "--host" in the backend, installer, tray and extension sources must either
give a loopback address or take the host from an explicit VLAW_HOST lookup. A literal 0.0.0.0, "::" or empty
host is only allowed where it comes from VLAW_HOST (the Docker image sets it explicitly in docker-compose.yml)."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_PARTS = {".venv", "node_modules", "tests", "dist", "out", "build", "__pycache__", "assets", "site-packages"}
WILDCARD = {"0.0.0.0", "::", "[::]", ""}

TEXT_SUFFIXES = {".bat", ".ps1", ".sh", ".iss", ".js", ".ts", ".yml", ".yaml", ".spec", ".cmd"}
ROOTS = [ROOT / "backend", ROOT / "installer", ROOT / "tray", ROOT / "vigil-vscode" / "src", ROOT / "docker-compose.yml", ROOT / "docker-compose.native.yml"]


def _files(suffixes):
    for base in ROOTS:
        candidates = [base] if base.is_file() else base.rglob("*") if base.exists() else []
        for path in candidates:
            if path.is_file() and not (set(path.relative_to(ROOT).parts) & SKIP_PARTS) and (path.suffix in suffixes or (path.name.startswith("Dockerfile") and ".py" not in suffixes)):
                yield path


def _is_vlaw_host_lookup(node) -> bool:
    """os.environ.get("VLAW_HOST", ...), os.environ["VLAW_HOST"], os.getenv("VLAW_HOST", ...), or a name bound from one."""
    text = ast.unparse(node)
    return "VLAW_HOST" in text and "VLAW_HOST_ROOT" not in text


def _python_problems(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            names[node.targets[0].id] = node.value
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("uvicorn.run") or (
                isinstance(node, ast.Call) and ast.unparse(node.func) == "run" and any(k.arg == "host" for k in node.keywords)):
            host = next((k.value for k in node.keywords if k.arg == "host"), None)
            where = f"{path.relative_to(ROOT)}:{node.lineno}"
            if host is None:
                continue  # uvicorn's own default is 127.0.0.1
            if isinstance(host, ast.Name) and host.id in names:
                host = names[host.id]
            if isinstance(host, ast.Constant):
                if host.value in WILDCARD:
                    problems.append(f"{where}: uvicorn.run binds {host.value!r} without a VLAW_HOST lookup")
            elif not _is_vlaw_host_lookup(host):
                problems.append(f"{where}: uvicorn.run host is {ast.unparse(host)!r}, not a constant loopback or a VLAW_HOST lookup")
    return problems


def _text_problems(path: Path) -> list[str]:
    problems = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        where = f"{path.relative_to(ROOT)}:{number}"
        for match in re.finditer(r"""--host(?:\s+|=)["']?([^\s"',\]]*)""", line):
            value = match.group(1)
            if (value in WILDCARD or value.startswith("0.0.0.0")) and "VLAW_HOST" not in line:
                problems.append(f"{where}: --host {value!r} without VLAW_HOST")
        if re.search(r"""["'=\s]0\.0\.0\.0["'\s,:)]|["'](::|\[::\])["']""", line) and "VLAW_HOST" not in line and not line.lstrip().startswith(("#", "//")):
            problems.append(f"{where}: a wildcard bind address without VLAW_HOST: {line.strip()[:80]}")
    return problems


def test_nothing_binds_all_interfaces_without_an_explicit_vlaw_host():
    problems = []
    for path in _files({".py"}):
        problems += _python_problems(path)
    for path in _files(TEXT_SUFFIXES):
        problems += _text_problems(path)
    assert problems == [], "\n".join(problems)


def test_run_native_and_main_take_the_same_loopback_default():
    for name in ("run_native.py", "main.py"):
        source = (ROOT / "backend" / name).read_text(encoding="utf-8")
        assert 'os.environ.get("VLAW_HOST", "127.0.0.1")' in source, name


def test_docker_sets_the_wildcard_explicitly_and_publishes_loopback_only():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert re.search(r"-\s*VLAW_HOST=0\.0\.0\.0", compose), "the container's wildcard bind must be an explicit setting"
    assert '"127.0.0.1:7422:7422"' in compose
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "${VLAW_HOST" in dockerfile and "ENV VLAW_HOST" not in dockerfile, "the image has no wildcard default"
    assert "0.0.0.0" not in dockerfile


def test_the_scanner_catches_the_old_run_native_line():
    old = 'import os, uvicorn\nuvicorn.run("main:app", host="0.0.0.0", port=7422, reload=False)\n'
    fixed = 'import os, uvicorn\nHOST = os.environ.get("VLAW_HOST", "127.0.0.1")\nuvicorn.run("main:app", host=HOST, port=7422)\n'
    inside = ROOT / "backend" / "_bind_scan_sample.py"  # _python_problems reports paths relative to the repo
    inside.write_text(old)
    try:
        assert _python_problems(inside), "a literal 0.0.0.0 must be reported"
        inside.write_text(fixed)
        assert _python_problems(inside) == []
    finally:
        inside.unlink()
