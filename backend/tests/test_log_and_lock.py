"""Tests for core/log_setup.py (rotation, quiet third-party loggers) and
core/instance_lock.py (single-instance lock in the data dir)."""

import logging
import os
import subprocess
import sys
import textwrap
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

from core import instance_lock
from core.instance_lock import InstanceAlreadyRunning, acquire_instance_lock, release_instance_lock
from core.log_setup import LOG_BACKUP_COUNT, LOG_MAX_BYTES, configure_logging

BACKEND_DIR = str(Path(__file__).resolve().parent.parent)


# ------------------------------------------------------------------ logging

@pytest.fixture
def clean_root_logging():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level  # pytest's own handlers stay in place
    saved_levels = {n: logging.getLogger(n).level for n in ("apscheduler", "watchdog")}
    yield root
    for h in root.handlers[:]:
        if h not in saved_handlers:
            root.removeHandler(h)
            h.close()
    root.setLevel(saved_level)
    for n, lvl in saved_levels.items():
        logging.getLogger(n).setLevel(lvl)


def test_log_file_handler_is_size_rotated(tmp_path, clean_root_logging):
    configure_logging(str(tmp_path / "x.log"), "INFO")
    # Other tests may import main.py, which installs its own rotating handler.
    rotating = [
        h for h in clean_root_logging.handlers
        if isinstance(h, RotatingFileHandler) and h.baseFilename == str(tmp_path / "x.log")
    ]
    assert len(rotating) == 1
    assert rotating[0].maxBytes == LOG_MAX_BYTES == 5 * 1024 * 1024
    assert rotating[0].backupCount == LOG_BACKUP_COUNT == 3


def test_log_actually_rotates(tmp_path, clean_root_logging, monkeypatch):
    monkeypatch.setattr("core.log_setup.LOG_MAX_BYTES", 2000)
    log = logging.getLogger("vlaw")
    configure_logging(str(tmp_path / "x.log"), "INFO")
    for i in range(200):
        log.info("line %d %s", i, "x" * 50)
    assert (tmp_path / "x.log.1").exists()


def test_scheduler_and_watchdog_loggers_are_warning(tmp_path, clean_root_logging):
    configure_logging(str(tmp_path / "x.log"), "INFO")
    assert logging.getLogger("apscheduler").level == logging.WARNING
    assert logging.getLogger("apscheduler.executors.default").getEffectiveLevel() == logging.WARNING
    assert logging.getLogger("watchdog").level == logging.WARNING
    assert not logging.getLogger("apscheduler.scheduler").isEnabledFor(logging.INFO)


# ------------------------------------------------------------ instance lock

def test_second_instance_is_refused(tmp_path):
    first = acquire_instance_lock(str(tmp_path))
    try:
        with pytest.raises(InstanceAlreadyRunning) as exc:
            acquire_instance_lock(str(tmp_path))
        assert exc.value.pid == os.getpid()
        # The refused attempt must not wipe the holder's pid text.
        assert (tmp_path / instance_lock.LOCK_FILENAME).read_text().strip() == str(os.getpid())
    finally:
        release_instance_lock(first)


def test_lock_can_be_retaken_after_release(tmp_path):
    release_instance_lock(acquire_instance_lock(str(tmp_path)))
    again = acquire_instance_lock(str(tmp_path))
    assert again is not None
    release_instance_lock(again)


def test_stale_lock_file_with_dead_pid_is_taken_over(tmp_path):
    (tmp_path / instance_lock.LOCK_FILENAME).write_text("999999999")
    f = acquire_instance_lock(str(tmp_path))
    try:
        assert f is not None
        assert (tmp_path / instance_lock.LOCK_FILENAME).read_text().strip() == str(os.getpid())
    finally:
        release_instance_lock(f)


def test_garbage_lock_file_is_taken_over(tmp_path):
    (tmp_path / instance_lock.LOCK_FILENAME).write_bytes(b"\xff\xfe not a pid \x00")
    f = acquire_instance_lock(str(tmp_path))
    assert f is not None
    release_instance_lock(f)


def test_unusable_lock_location_does_not_block_startup(tmp_path):
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    # data_dir is a path under a regular file: makedirs/open fail.
    assert acquire_instance_lock(str(blocker / "sub")) is None


def test_crashed_holder_releases_lock(tmp_path):
    """A holder that is killed (no clean release) must not leave a lock
    that survives it: the OS drops it with the process."""
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {BACKEND_DIR!r})
        from core.instance_lock import acquire_instance_lock
        f = acquire_instance_lock({str(tmp_path)!r})
        print("held", flush=True)
        time.sleep(60)
    """)
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "held"
        with pytest.raises(InstanceAlreadyRunning) as exc:
            acquire_instance_lock(str(tmp_path))
        assert exc.value.pid == proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=10)
        if proc.stdout:
            proc.stdout.close()
    f = acquire_instance_lock(str(tmp_path))
    assert f is not None
    release_instance_lock(f)
