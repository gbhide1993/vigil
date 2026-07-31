#!/usr/bin/env python3
"""vigil install-hook / vigil uninstall-hook

Installs (or removes) scripts/vigil-post-commit.py as .git/hooks/post-commit
in a target repo, so every commit automatically gets Vigil evidence attached
via git notes. Safe to run repeatedly; never touches an existing non-Vigil
hook beyond appending to it.
"""

import argparse
import sys
import urllib.request
from pathlib import Path

VIGIL_VERSION = "0.2.1-beta"
VIGIL_MARKER = "# Vigil evidence hook"
VIGIL_URL = "http://localhost:7422/git/commit-summary"
HOOK_SOURCE = Path(__file__).parent / "vigil-post-commit.py"


def _hook_path(repo: Path) -> Path:
    return repo / ".git" / "hooks" / "post-commit"


def _check_api() -> bool:
    try:
        with urllib.request.urlopen(VIGIL_URL, timeout=3):
            return True
    except Exception:
        return False


def install(repo: Path) -> int:
    if not (repo / ".git").exists():
        print(f"Error: {repo} is not a git repository (.git not found)")
        return 1

    hook_path = _hook_path(repo)
    hook_path.parent.mkdir(parents=True, exist_ok=True)

    vigil_script = HOOK_SOURCE.read_text(encoding="utf-8")

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if VIGIL_MARKER not in existing:
            print("Existing post-commit hook found.")
            with open(hook_path, "a", encoding="utf-8") as f:
                f.write("\n\n# --- Vigil evidence hook appended below ---\n")
                f.write(vigil_script)
        else:
            hook_path.write_text(vigil_script, encoding="utf-8")
    else:
        hook_path.write_text(vigil_script, encoding="utf-8")

    try:
        import os
        import stat

        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    print(f"✓ Vigil git hook installed: {hook_path}")
    if _check_api():
        print("✓ Vigil API: reachable")
    else:
        print("⚠ Vigil API: not running (hook will activate when Vigil starts)")

    return 0


def uninstall(repo: Path) -> int:
    if not (repo / ".git").exists():
        print(f"Error: {repo} is not a git repository (.git not found)")
        return 1

    hook_path = _hook_path(repo)
    if not hook_path.exists():
        print("No post-commit hook found.")
        return 0

    if VIGIL_MARKER not in hook_path.read_text(encoding="utf-8"):
        print("post-commit hook exists but is not a Vigil hook — not removing.")
        return 1

    hook_path.unlink()
    print(f"✓ Vigil git hook removed: {hook_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="vigil")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install-hook")
    install_parser.add_argument("--repo", default=".")

    uninstall_parser = subparsers.add_parser("uninstall-hook")
    uninstall_parser.add_argument("--repo", default=".")

    args = parser.parse_args()
    repo = Path(args.repo).resolve()

    if args.command == "install-hook":
        return install(repo)
    return uninstall(repo)


if __name__ == "__main__":
    sys.exit(main())
