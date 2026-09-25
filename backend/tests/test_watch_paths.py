from core.red_lines import SESSION_LAUNCH_DIR
from main import build_watch_paths


def test_flat_credential_pattern_still_watches_session_launch_dir():
    """credential_paths=['.env'] has no directory component and would
    otherwise be silently dropped by the endswith('/'|'\\\\')/startswith('~')
    filter, leaving nothing watching the project root for a .env edit."""
    policy = {"scope_directories": [], "credential_paths": [".env"]}
    watch_paths, _ = build_watch_paths(policy)
    assert str(SESSION_LAUNCH_DIR) in watch_paths


def test_scope_directories_included_when_credential_paths_flat():
    policy = {"scope_directories": ["/some/project"], "credential_paths": [".env"]}
    watch_paths, _ = build_watch_paths(policy)
    assert "/some/project" in watch_paths


def test_no_credential_paths_does_not_add_session_launch_dir_twice():
    """When credential_paths is empty, the flat-pattern fallback must not
    fire — SESSION_LAUNCH_DIR should only appear via the existing
    red_line_non_recursive_dirs path, not injected into watch_paths."""
    policy = {"scope_directories": [], "credential_paths": []}
    watch_paths, red_line_non_recursive_dirs = build_watch_paths(policy)
    assert str(SESSION_LAUNCH_DIR) not in watch_paths
    assert str(SESSION_LAUNCH_DIR) in red_line_non_recursive_dirs


def test_directory_style_credential_paths_still_watched_directly():
    """Existing behavior for a directory-shaped credential_paths entry
    (e.g. '~/.ssh/') must be unaffected by the flat-pattern fix. Expansion
    of '~' happens later in file_watcher._schedule_paths, not here, so the
    raw policy string is what should appear in watch_paths."""
    policy = {"scope_directories": [], "credential_paths": ["~/.ssh/"]}
    watch_paths, _ = build_watch_paths(policy)
    assert "~/.ssh/" in watch_paths
