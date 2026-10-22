"""Proves the two protections in tests/_sandbox_guard.py (installed by conftest.py) without touching the real
%LOCALAPPDATA%\\V-LAW: every "real" folder below is a stand-in inside tmp_path that the guard is told to protect."""

import os
import shutil
from pathlib import Path

import pytest

import _sandbox_guard as guard


@pytest.fixture
def stand_in(tmp_path):
    """A fake 'real' V-LAW folder with the same shape (data, keys, policy, trial marker), registered with the guard."""
    real = tmp_path / "Local" / "V-LAW"
    for sub in ("data", "keys", "policy"):
        (real / sub).mkdir(parents=True)
        (real / sub / "file.txt").write_text("keep me")
    (real / ".vlaw-trial-started").write_text("marker")
    before = guard.real_dirs()
    guard.set_real_dirs([real])
    yield real
    guard.set_real_dirs(before)


def _intact(real: Path) -> bool:
    return all((real / sub / "file.txt").read_text() == "keep me" for sub in ("data", "keys", "policy")) and (real / ".vlaw-trial-started").exists()


# ------------------------------------------------ (a) the start-up check

@pytest.mark.parametrize("variable", guard.PATH_VARIABLES)
def test_startup_check_fails_when_a_variable_points_into_the_real_folder(stand_in, variable):
    env = {variable: str(stand_in / "data" / "x")}
    with pytest.raises(pytest.UsageError, match="real Vigil data folder"):
        guard.check_session_paths(env, None)


def test_startup_check_fails_for_the_real_folder_itself_and_for_a_parent_of_it(stand_in):
    for value in (str(stand_in), str(stand_in.parent)):
        with pytest.raises(pytest.UsageError):
            guard.check_session_paths({"VLAW_DATA_DIR": value}, None)


def test_startup_check_fails_when_main_would_use_the_real_folder_as_its_base_dir(stand_in):
    with pytest.raises(pytest.UsageError, match="main.BASE_DIR"):
        guard.check_session_paths({}, str(stand_in))


def test_startup_check_passes_for_temp_paths(stand_in, tmp_path):
    env = {name: str(tmp_path / "elsewhere" / name) for name in guard.PATH_VARIABLES}
    guard.check_session_paths(env, str(tmp_path / "backend"))


def test_basetemp_inside_or_above_the_real_folder_is_refused(stand_in, tmp_path):
    for value in (stand_in, stand_in / "data", stand_in.parent):
        with pytest.raises(pytest.UsageError, match="--basetemp"):
            guard.check_basetemp(value)
    guard.check_basetemp(tmp_path / "somewhere-else")
    guard.check_basetemp(None)
    assert _intact(stand_in)


def test_this_run_is_redirected_away_from_the_real_folder():
    """The live proof for the run you are in: conftest's redirect is in force and the guard knows the real folder."""
    assert guard.real_dirs(), "conftest must register the real folder"
    for name in guard.PATH_VARIABLES + ("LOCALAPPDATA",):
        value = os.environ.get(name)
        if value:
            assert not guard.touches_real(value), f"{name}={value} is the real Vigil data folder"
    import db.database as database

    assert not guard.touches_real(database.DATA_DIR) and not guard.touches_real(database.DB_PATH)


# ------------------------------------------------ (b) the delete guard

def test_rmtree_of_the_real_folder_or_any_part_of_it_is_refused(stand_in):
    for target in (stand_in, stand_in / "keys", stand_in / "data", stand_in / "policy", stand_in.parent):
        with pytest.raises(guard.SandboxViolation):
            shutil.rmtree(target)
        with pytest.raises(guard.SandboxViolation):
            shutil.rmtree(target, ignore_errors=True)
    assert _intact(stand_in)


def test_rmdir_and_path_rmdir_of_the_real_folder_are_refused(stand_in):
    with pytest.raises(guard.SandboxViolation):
        os.rmdir(stand_in / "policy")
    with pytest.raises(guard.SandboxViolation):
        (stand_in / "policy").rmdir()
    assert _intact(stand_in)


def test_deleting_files_inside_the_real_folder_is_refused(stand_in):
    for delete in (os.remove, os.unlink, lambda p: Path(p).unlink()):
        with pytest.raises(guard.SandboxViolation):
            delete(stand_in / "data" / "file.txt")
        with pytest.raises(guard.SandboxViolation):
            delete(stand_in / ".vlaw-trial-started")
    assert _intact(stand_in)


def test_the_guard_is_not_swallowed_by_except_oserror(stand_in):
    try:
        try:
            shutil.rmtree(stand_in)
        except OSError:
            pytest.fail("a violation must not look like an OSError")
    except guard.SandboxViolation:
        pass
    assert _intact(stand_in)


def test_a_directory_outside_the_temp_dir_is_refused_even_if_it_is_not_the_real_folder():
    """Nothing is created: the guard decides from the path alone, before looking at the disk."""
    outside = Path.home() / "_vlaw_guard_probe_does_not_exist"
    assert not guard._dir_allowed(outside)
    with pytest.raises(guard.SandboxViolation, match="only be deleted under"):
        shutil.rmtree(outside)
    with pytest.raises(guard.SandboxViolation):
        os.rmdir(outside)
    assert not outside.exists()


def test_deleting_under_the_temp_dir_still_works(tmp_path):
    folder = tmp_path / "scratch"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "f.txt").write_text("x")
    (folder / "lone.txt").write_text("x")
    (folder / "lone.txt").unlink()
    os.remove(folder / "sub" / "f.txt")
    (folder / "sub").rmdir()
    shutil.rmtree(folder)
    assert not folder.exists()


def test_the_crash_recovery_log_path_cannot_reach_the_real_folder(tmp_path):
    """core/aggregator.py builds %LOCALAPPDATA%\\V-LAW\\crash_recovery.log itself and unlinks it."""
    from core.aggregator import _crash_recovery_path

    assert not guard.touches_real(_crash_recovery_path())


def test_the_guard_is_installed_for_the_whole_session():
    assert guard._originals, "conftest.py must call guard.install()"
    assert shutil.rmtree is not guard._originals["rmtree"]


# ------------------------------------------------ the whole run fails at start (a real pytest child process)

def _child_pytest(tmp_path, extra_env=None, extra_args=()):
    """Runs a real pytest on one trivial test with a stand-in LOCALAPPDATA. Never the real folder."""
    import subprocess
    import sys

    local = tmp_path / "Local"
    real = local / "V-LAW"
    (real / "data").mkdir(parents=True)
    (real / "data" / "vlaw.db").write_text("evidence")
    env = {k: v for k, v in os.environ.items() if k not in guard.PATH_VARIABLES}
    env["LOCALAPPDATA"] = str(local)
    env.update(extra_env or {})
    env = {k: (v.replace("{real}", str(real)) if isinstance(v, str) else v) for k, v in env.items()}
    args = [a.replace("{real}", str(real)) for a in extra_args]
    backend = Path(__file__).resolve().parents[1]
    # One cheap test of this very file as the probe, so the child loads this conftest.py.
    probe = "tests/test_sandbox_guard.py::test_the_guard_is_installed_for_the_whole_session"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", probe, *args],
        cwd=str(backend), env=env, capture_output=True, text=True, timeout=120,
    )
    return result, real


def test_a_run_whose_data_dir_is_the_real_folder_fails_before_any_test(tmp_path):
    result, real = _child_pytest(tmp_path, {"VLAW_DATA_DIR": "{real}/data"})
    assert result.returncode != 0 and "real Vigil data folder" in result.stdout + result.stderr
    assert "1 passed" not in result.stdout
    assert (real / "data" / "vlaw.db").read_text() == "evidence"


def test_a_run_whose_basetemp_is_the_real_folder_fails_before_pytest_empties_it(tmp_path):
    result, real = _child_pytest(tmp_path, extra_args=("--basetemp={real}",))
    assert result.returncode != 0 and "--basetemp" in result.stdout + result.stderr
    assert (real / "data" / "vlaw.db").read_text() == "evidence", "pytest must not have emptied the folder"


# ------------------------------------------------ pytest's own cache clean-up is allowed, nothing else is

@pytest.fixture
def fake_backend(tmp_path, monkeypatch):
    """A stand-in backend directory that is NOT under an allowed root, so only the pytest-cache rule can allow it."""
    backend = tmp_path / "backend"
    (backend / "core").mkdir(parents=True)
    monkeypatch.setattr(guard, "_BACKEND_DIR", str(backend))
    monkeypatch.setattr(guard, "_allowed_roots", [])
    return backend


def test_pytest_cache_temp_dir_inside_backend_is_allowed(fake_backend):
    for name in ("pytest-cache-files-isy0lybc", ".pytest_cache"):
        folder = fake_backend / name
        (folder / "v" / "cache").mkdir(parents=True)
        (folder / "v" / "cache" / "lastfailed").write_text("{}")
        shutil.rmtree(folder)
        assert not folder.exists()
    nested = fake_backend / ".pytest_cache" / "d" / "x"
    nested.mkdir(parents=True)
    os.rmdir(nested)                                    # under .pytest_cache


def test_other_backend_folders_and_lookalikes_are_still_refused(fake_backend):
    for target in (fake_backend / "core", fake_backend, fake_backend.parent / "pytest-cache-files-abc",
                   fake_backend / "core" / "pytest-cache-files-abc", fake_backend / "my.pytest_cache"):
        with pytest.raises(guard.SandboxViolation):
            shutil.rmtree(target)
    assert (fake_backend / "core").is_dir()


def test_the_real_folder_its_parent_and_what_is_around_it_stay_refused_even_inside_the_cache_rule(stand_in, monkeypatch):
    """The cache rule is checked after the real-folder rule, also when the stand-in sits under the 'backend' dir."""
    monkeypatch.setattr(guard, "_BACKEND_DIR", str(stand_in.parent.parent))
    nested_cache = stand_in / "pytest-cache-files-zzz"
    nested_cache.mkdir()
    for target in (stand_in, stand_in.parent, stand_in / "keys", nested_cache):
        with pytest.raises(guard.SandboxViolation):
            shutil.rmtree(target)
    assert _intact(stand_in) and nested_cache.is_dir()


def test_the_real_backend_core_folder_is_refused_in_this_run():
    core = Path(guard._BACKEND_DIR) / "core"
    assert core.is_dir() and not guard._dir_allowed(core)
    with pytest.raises(guard.SandboxViolation):
        shutil.rmtree(core)
    assert core.is_dir()
    assert guard._is_pytest_cache_path(Path(guard._BACKEND_DIR) / "pytest-cache-files-isy0lybc")
