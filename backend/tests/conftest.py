"""Session-wide test setup.

VLAW_DATA_DIR must be set to an isolated temp directory BEFORE db.database
is imported anywhere in the process -- its DATA_DIR/DB_PATH module-level
constants are computed once, at first import, from that env var. Several
existing test modules import `main` (which imports db.database) at
collection time, so this has to happen here, in conftest.py, which pytest
loads before it collects/imports any test module in this directory --
setting it inside a fixture would run too late for whichever test module
gets imported first.
"""

import os
import tempfile

import _sandbox_guard as guard

# The real per-user folder, captured BEFORE anything below changes LOCALAPPDATA. Whatever a run would use for its
# data, keys, policy or license, or for main.BASE_DIR, must not be this folder (or inside it): the run stops here,
# before a single backend module is imported.
guard.set_real_dirs([guard.real_vlaw_dir()])
guard.check_session_paths(os.environ, guard.expected_base_dir(os.environ))

os.environ.setdefault("VLAW_DATA_DIR", tempfile.mkdtemp(prefix="vlaw_test_data_"))
# Code that builds %LOCALAPPDATA%\V-LAW itself (core/aggregator.py's crash_recovery.log, core/own_paths.py) must land in
# this run's temp directory too, also for tests that forget to monkeypatch it. Forced, not setdefault.
os.environ["LOCALAPPDATA"] = os.path.join(os.environ["VLAW_DATA_DIR"], "localappdata")
os.makedirs(os.environ["LOCALAPPDATA"], exist_ok=True)
# The evidence anchor counter lives outside the database (core/evidence_anchor.py). Keep it inside this run's
# temp directory so a test run never reads another run's key directory.
os.environ.setdefault("VLAW_KEY_DIR", os.path.join(os.environ["VLAW_DATA_DIR"], "keys"))
guard.check_session_paths(os.environ, guard.expected_base_dir(os.environ))   # again, with every variable now set
guard.allow_root(guard.system_temp())
guard.allow_root(os.environ["VLAW_DATA_DIR"])
guard.install()


def pytest_configure(config):
    """--basetemp is emptied by pytest itself at start-up; refuse it if it is (or contains) the real folder."""
    basetemp = getattr(config.option, "basetemp", None)
    guard.check_basetemp(basetemp)
    guard.allow_root(basetemp)


def pytest_sessionfinish(session, exitstatus):
    """aiosqlite.Connection runs as a non-daemon background thread (see
    test_db's own fixture docstring in test_bugfixes.py) -- Python will
    not exit while any non-daemon thread is still alive. Every test that
    uses the test_db fixture closes its own connection on teardown, but
    that only covers the shared db.database._db singleton; if any test
    anywhere leaves it open (a skipped teardown, an exception during
    close, a test that never went through that fixture at all), this
    thread leak is otherwise invisible until it silently keeps the whole
    pytest process alive long after "N passed" has already printed. This
    runs once, after every test has finished, as a last-resort safety
    net -- not a substitute for each test closing its own connection."""
    import asyncio

    import db.database as database

    if database._db is not None:
        asyncio.run(database.close_db())
