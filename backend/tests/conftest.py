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
