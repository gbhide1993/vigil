import os

from core.red_lines import SESSION_LAUNCH_DIR
from main import build_watch_paths


def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(p))).replace("\\", "/")


def test_backend_launch_directory_is_never_watched():
    """The installed backend's working directory is Vigil's own install
    folder, not the user's project, so it must not be watched in any
    configuration (including flat credential patterns like '.env')."""
    for policy in (
        {"scope_directories": [], "credential_paths": [".env"]},
        {"scope_directories": [], "credential_paths": [".ssh", ".aws"]},
        {"scope_directories": [], "credential_paths": []},
        {},
    ):
        watch_paths, non_recursive = build_watch_paths(policy)
        launch = _norm(str(SESSION_LAUNCH_DIR))
        assert launch not in [_norm(p) for p in watch_paths]
        assert launch not in [_norm(p) for p in non_recursive]
        assert non_recursive == []


def test_hard_coded_ssh_and_claude_cache_watches_remain():
    watch_paths, _ = build_watch_paths({"scope_directories": [], "credential_paths": []})
    normalised = [_norm(p) for p in watch_paths]
    assert _norm("~/.ssh/") in normalised
    assert _norm("~/.claude/file-history/") in normalised
    assert len(watch_paths) == 2


def test_scope_directories_are_watched_once_each():
    policy = {"scope_directories": ["/some/project", "/other/project"], "credential_paths": [".env"]}
    watch_paths, _ = build_watch_paths(policy)
    assert watch_paths.count("/some/project") == 1
    assert watch_paths.count("/other/project") == 1


def test_project_config_folders_are_covered_by_each_scope_directory():
    """.claude / .cursor / .vscode (and a root .mcp.json) live under a scope
    directory, so the recursive watch of that directory covers them. They
    are not scheduled again (a second watch would double every event), and
    nothing outside the scope directories is added for them."""
    scope = os.path.abspath("some_project_dir")
    watch_paths, _ = build_watch_paths({"scope_directories": [scope], "credential_paths": []})
    roots = [_norm(p) for p in watch_paths]
    for config_dir in (".claude", ".cursor", ".vscode"):
        target = _norm(os.path.join(scope, config_dir))
        assert any(target == root or target.startswith(root + "/") for root in roots)
    assert not any(_norm(os.path.join(scope, c)) in roots for c in (".claude", ".cursor", ".vscode"))


def test_directory_style_credential_paths_still_watched_directly():
    """A directory-shaped credential_paths entry (e.g. '~/.aws/') is still
    watched; '~' is expanded later in file_watcher._schedule_paths."""
    watch_paths, _ = build_watch_paths({"scope_directories": [], "credential_paths": ["~/.aws/"]})
    assert "~/.aws/" in watch_paths
