"""Keeps a test run away from the real %LOCALAPPDATA%\\V-LAW folder (data, keys, policy, license, backups, logs).

Two protections, both installed by conftest.py before any backend module is imported:

1. Start-up check: if the data, key, policy or license path a run would use (or the base directory main.py would
   pick) is the real V-LAW folder or inside it, or --basetemp is, the whole run fails before the first test.
2. Delete guard: shutil.rmtree / os.rmdir refuse any directory that is not under the temp directory (or this run's
   --basetemp), and every delete (files too) refuses anything inside the real V-LAW folder or any folder above it.

It guards this process only. Child processes (test_runtime_state starts the backend) get their own redirected
environment from the test that starts them.
"""

import contextlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# Environment variables the backend turns into paths (main.py, db/database.py, core/evidence_anchor.py).
PATH_VARIABLES = ("VLAW_DATA_DIR", "VLAW_KEY_DIR", "VLAW_POLICY_FILE", "VLAW_LICENSE_FILE")


class SandboxViolation(RuntimeError):
    """Not an OSError on purpose: code that does `except OSError: pass` around a delete must not hide it."""


def _norm(path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(os.fspath(path))))


def _inside(path, root) -> bool:
    path, root = _norm(path), _norm(root)
    return path == root or path.startswith(root.rstrip("\\/") + os.sep)


_real_dirs: list[str] = []
_allowed_roots: list[str] = []
_originals: dict = {}
_bypass = 0


def real_vlaw_dir(local_app_data: str | None = None) -> str:
    """The folder the installed Vigil uses, worked out the way main.py's get_base_path does."""
    base = local_app_data or os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "V-LAW")


def set_real_dirs(dirs) -> None:
    _real_dirs[:] = [str(d) for d in dirs]


def real_dirs() -> list[str]:
    return list(_real_dirs)


def allow_root(root) -> None:
    if root:
        _allowed_roots.append(str(root))


def allowed_roots() -> list[str]:
    return list(_allowed_roots)


def touches_real(path) -> bool:
    """True if `path` is the real V-LAW folder, inside it, or a folder that contains it (deleting the parent
    would delete it too)."""
    return any(_inside(path, real) or _inside(real, path) for real in _real_dirs)


def check_session_paths(env, base_dir: str | None, real_dirs_=None) -> None:
    """Fails the run (pytest.UsageError) if any path this run would use is the real V-LAW folder."""
    reals = list(real_dirs_ if real_dirs_ is not None else _real_dirs)
    candidates = {name: env[name] for name in PATH_VARIABLES if env.get(name)}
    if base_dir:
        candidates["main.BASE_DIR"] = base_dir
    for name, value in candidates.items():
        for real in reals:
            if _inside(value, real) or _inside(real, value):
                raise pytest.UsageError(
                    f"Refusing to run: {name}={value!r} resolves to the real Vigil data folder {real!r}. "
                    "Unset it, or point it at a temp directory."
                )


def expected_base_dir(env) -> str | None:
    """main.get_base_path() without importing main: the per-user V-LAW folder when frozen, else the backend folder."""
    if getattr(sys, "frozen", False):
        return real_vlaw_dir(env.get("LOCALAPPDATA"))
    return str(Path(__file__).resolve().parents[1])


def check_basetemp(basetemp) -> None:
    """pytest empties --basetemp when it starts, so pointing it at the real folder (or above it) deletes it."""
    if not basetemp:
        return
    for real in _real_dirs:
        if _inside(basetemp, real) or _inside(real, basetemp):
            raise pytest.UsageError(f"Refusing to run: --basetemp {str(basetemp)!r} is or contains the real Vigil data folder {real!r}.")


@contextlib.contextmanager
def bypass():
    """For the guard's own tests only."""
    global _bypass
    _bypass += 1
    try:
        yield
    finally:
        _bypass -= 1


def _dir_allowed(path) -> bool:
    return any(_inside(path, root) for root in _allowed_roots)


def _check_directory_delete(path, what: str) -> None:
    if _bypass:
        return
    if touches_real(path):
        raise SandboxViolation(f"{what}({os.fspath(path)!r}) would delete the real Vigil data folder")
    if not _dir_allowed(path):
        raise SandboxViolation(f"{what}({os.fspath(path)!r}): directories may only be deleted under {_allowed_roots}")


def _check_file_delete(path, what: str) -> None:
    if not _bypass and touches_real(path):
        raise SandboxViolation(f"{what}({os.fspath(path)!r}) is inside the real Vigil data folder")


def install() -> None:
    """Replaces the delete functions for this process. Safe to call twice."""
    if _originals:
        return
    _originals.update(rmtree=shutil.rmtree, rmdir=os.rmdir, remove=os.remove, unlink=os.unlink)

    def rmtree(path, *args, **kwargs):
        _check_directory_delete(path, "shutil.rmtree")
        return _originals["rmtree"](path, *args, **kwargs)

    def rmdir(path, *args, dir_fd=None, **kwargs):
        if dir_fd is None:                      # a relative name under an open directory cannot be resolved here
            _check_directory_delete(path, "os.rmdir")
        return _originals["rmdir"](path, *args, dir_fd=dir_fd, **kwargs)

    def remove(path, *args, dir_fd=None, **kwargs):
        if dir_fd is None:
            _check_file_delete(path, "os.remove")
        return _originals["remove"](path, *args, dir_fd=dir_fd, **kwargs)

    def unlink(path, *args, dir_fd=None, **kwargs):
        if dir_fd is None:
            _check_file_delete(path, "os.unlink")
        return _originals["unlink"](path, *args, dir_fd=dir_fd, **kwargs)

    shutil.rmtree, os.rmdir, os.remove, os.unlink = rmtree, rmdir, remove, unlink


def uninstall() -> None:
    if _originals:
        shutil.rmtree, os.rmdir, os.remove, os.unlink = (_originals[k] for k in ("rmtree", "rmdir", "remove", "unlink"))
        _originals.clear()


def system_temp() -> str:
    return tempfile.gettempdir()
