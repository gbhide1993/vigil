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

os.environ.setdefault("VLAW_DATA_DIR", tempfile.mkdtemp(prefix="vlaw_test_data_"))


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
