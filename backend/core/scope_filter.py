"""In-memory scope filter for the ETW tier.

Kernel file tracing delivers every file operation on the computer. Most of it comes from a recognised agent's
process tree (a desktop app's cache and crash-report files, npm's logs) in folders nobody asked Vigil to watch, and
each such event used to cost an agent lookup and database writes before anything decided it did not matter. This
decides first, from memory only: an event goes on only if its path is

  - under a watched root (the project folders, the credential folders and the never-scope folders of the policy), or
  - a credential path (the same test the aggregator uses: .env, .ssh, .aws, .pem, .key), or
  - under an agent's own state folder (~/.claude, ~/.codex), or
  - a persistence location: somewhere a write makes code run later, outside any project (the user's Startup folder,
    PowerShell profiles, the shell profiles in the home folder, ~/.gitconfig).

Everything else is counted in memory (core/watch_stats.py) and never recorded. This is a narrower view than "every
change a recognised agent makes anywhere"; the report notes and docs/COVERAGE.md say so.

Until the roots are first set (start-up) the filter lets everything through rather than dropping events it has no
basis to judge.
"""

import os
import threading

from core.attribution import agent_for_path


def _key(path: str) -> str:
    return path.replace("\\", "/").lower().rstrip("/")


class ScopeFilter:
    def __init__(self) -> None:
        self._roots: tuple[str, ...] | None = None
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        return self._roots is not None

    def roots(self) -> list[str]:
        return list(self._roots or ())

    def set_roots(self, paths) -> None:
        keys = tuple(sorted({_key(os.path.expanduser(p)) for p in paths if p}))
        with self._lock:
            self._roots = keys

    def add_root(self, path: str) -> None:
        with self._lock:
            self._roots = tuple(sorted(set(self._roots or ()) | {_key(os.path.expanduser(path))}))

    def remove_root(self, path: str) -> None:
        with self._lock:
            self._roots = tuple(r for r in (self._roots or ()) if r != _key(os.path.expanduser(path)))

    def allows(self, path: str) -> bool:
        roots = self._roots
        if roots is None:
            return True
        key = _key(path)
        for root in roots:
            if key == root or key.startswith(root + "/"):
                return True
        if agent_for_path(path) is not None:
            return True
        return _is_sensitive(key) or _is_persistence(key)


def _is_sensitive(key: str) -> bool:
    # The aggregator's own credential test (core/aggregator.py), imported lazily: that module is heavy and imports
    # most of the backend.
    from core.aggregator import CREDENTIAL_PATTERNS

    return any(pattern in key for pattern in CREDENTIAL_PATTERNS)


# Files directly in the home folder that a shell or git reads at the start of every session.
_HOME_PERSISTENCE_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".gitconfig",
)
# PowerShell runs these at the start of every session (Windows PowerShell 5.1, PowerShell 7, the VS Code host, the ISE).
_POWERSHELL_PROFILE_FOLDERS = ("/windowspowershell/", "/powershell/")
_POWERSHELL_PROFILE_SUFFIXES = ("profile.ps1",)   # profile.ps1, Microsoft.PowerShell_profile.ps1, Microsoft.VSCode_profile.ps1, ...


def _startup_folder_key() -> str:
    appdata = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
    return _key(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))


def _is_persistence(key: str) -> bool:
    """`key` is a lower-case, forward-slash path (see _key)."""
    startup = _startup_folder_key()
    if key == startup or key.startswith(startup + "/"):
        return True
    home = _key(os.path.expanduser("~"))
    if key.startswith(home + "/") and "/" not in key[len(home) + 1:] and key[len(home) + 1:] in _HOME_PERSISTENCE_FILES:
        return True
    name = key.rsplit("/", 1)[-1]
    return name.endswith(_POWERSHELL_PROFILE_SUFFIXES) and any(folder in key for folder in _POWERSHELL_PROFILE_FOLDERS)


# The filter the running backend uses; main.py sets its roots at start-up and the scope API keeps them current.
etw_scope = ScopeFilter()
