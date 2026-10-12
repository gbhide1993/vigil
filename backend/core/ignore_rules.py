"""One shared rule for file changes that are never recorded because they
happen in generated or dependency folders (node_modules, build outputs,
caches, virtual environments, most of .git). On a real repository these
produce thousands of events per `npm install` or build; the rule is applied
at the very start of every watcher entry point (native and polling
observers, and the ETW tier), before attribution, aggregation or any
database work.

Never ignored, anywhere:
  - credential-looking paths (.env, .ssh, .aws, .pem, .key ... the same
    definition the aggregator uses to classify credential access), even
    inside node_modules (except public CA bundles such as certifi's cacert.pem,
    see aggregator._is_public_ca_bundle);
  - the security-relevant parts of git: .git/hooks, .git/config (and the
    same two inside .git/modules/<name>/), plus .gitmodules, which is not
    under .git at all. A write to one of those can run code or redirect
    fetches, so it stays visible. The rest of .git (objects, refs, logs,
    index, packed files) is ignored.

Each ignored change is counted per folder (core/watch_stats.py) and the
report states the total. VLAW_IGNORE_GENERATED=0 switches the rule off.
"""

import os

from core import watch_stats
from core.aggregator import _is_credential_path, _is_public_ca_bundle

IGNORED_DIR_NAMES = frozenset({
    "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".nuxt", "target",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "coverage", ".nyc_output", ".cache", ".gradle",
    "site-packages",
})


def is_enabled() -> bool:
    return os.environ.get("VLAW_IGNORE_GENERATED", "1").strip().lower() not in ("0", "false", "no")


def _git_internal_is_meaningful(rest: list[str]) -> bool:
    """rest = the lower-cased path segments after a `.git` segment."""
    if not rest:
        return False
    if rest[0] == "hooks" or rest == ["config"]:
        return True
    if rest[0] == "modules" and len(rest) >= 3:    # .git/modules/<submodule>/hooks | config
        return rest[2] == "hooks" or rest[2:] == ["config"]
    return False


def ignored_folder_for(path: str | None) -> str | None:
    """The folder name that makes `path` ignorable ("node_modules", ".git", ...),
    or None if the change must be recorded."""
    if not path:
        return None
    if _is_credential_path(path):
        return None
    segments = [s.lower() for s in path.replace("\\", "/").split("/")]
    for index, segment in enumerate(segments):
        if segment in IGNORED_DIR_NAMES:
            return segment
        if segment == ".git":
            return None if _git_internal_is_meaningful(segments[index + 1:]) else ".git"
    # A public CA bundle (cacert.pem ...) in a certifi folder that is not itself
    # inside a generated folder: still an ordinary generated file.
    if _is_public_ca_bundle(path):
        return "certifi"
    return None


def ignore_and_count(path: str | None) -> bool:
    """True if this change is in an ignored folder; counts it. Cheap enough
    to call on every raw watcher event."""
    if not is_enabled():
        return False
    folder = ignored_folder_for(path)
    if folder is None:
        return False
    watch_stats.count_ignored(folder)
    return True
