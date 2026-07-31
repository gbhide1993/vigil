"""SQLite connection manager. Single get_db() entry point used by the
rest of the backend — no other module should open its own connection."""

import json
import logging
import os
import sys
from pathlib import Path

import aiosqlite

logger = logging.getLogger("vlaw")

SCHEMA_VERSION = 1

DATA_DIR = Path(os.environ.get("VLAW_DATA_DIR", "./data"))
DB_PATH = DATA_DIR / "vlaw.db"
# schema.sql is a read-only bundled asset: PyInstaller unpacks it under
# sys._MEIPASS at runtime, not next to this file.
SCHEMA_PATH = Path(sys._MEIPASS) / "db" / "schema.sql" if getattr(sys, "frozen", False) else Path(__file__).parent / "schema.sql"
POLICY_FILE = Path(os.environ.get("VLAW_POLICY_FILE", "./policy/vlaw-policy.json"))

_db: aiosqlite.Connection | None = None


async def init_db() -> aiosqlite.Connection:
    """Create the DB file, run schema.sql, and seed default policy.
    Safe to call on every startup — all statements are idempotent."""
    global _db

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    _db = await aiosqlite.connect(DB_PATH)
    await _db.execute("PRAGMA busy_timeout = 5000")
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA foreign_keys = ON")

    schema_sql = SCHEMA_PATH.read_text()
    await _db.executescript(schema_sql)
    await _db.commit()

    cur = await _db.execute("PRAGMA user_version")
    current_version = (await cur.fetchone())[0]
    if current_version < SCHEMA_VERSION:
        await _db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        await _db.commit()
        logger.info("schema version updated %d -> %d", current_version, SCHEMA_VERSION)

    await _migrate(_db)
    await _seed_policy(_db)

    return _db


async def _migrate(db: aiosqlite.Connection) -> None:
    """Column additions for DBs created before a given column existed.
    CREATE TABLE IF NOT EXISTS in schema.sql doesn't retrofit existing
    tables, so new columns need an explicit, idempotent ALTER TABLE here."""
    cur = await db.execute("PRAGMA table_info(alerts)")
    columns = {row["name"] for row in await cur.fetchall()}
    if "rule_type" not in columns:
        await db.execute("ALTER TABLE alerts ADD COLUMN rule_type TEXT DEFAULT 'policy'")
        await db.commit()
    if "session_id" not in columns:
        await db.execute("ALTER TABLE alerts ADD COLUMN session_id TEXT")
        await db.commit()

    cur = await db.execute("PRAGMA table_info(sessions)")
    columns = {row["name"] for row in await cur.fetchall()}
    if "summary" not in columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN summary TEXT")
        await db.commit()


async def _seed_policy(db: aiosqlite.Connection) -> None:
    if not POLICY_FILE.exists():
        return

    policy = json.loads(POLICY_FILE.read_text())
    for key, value in policy.items():
        await db.execute(
            """
            INSERT INTO policy (policy_key, policy_value)
            VALUES (?, ?)
            ON CONFLICT(policy_key) DO NOTHING
            """,
            (key, json.dumps(value)),
        )
    await db.commit()


async def get_db() -> aiosqlite.Connection:
    """Return the shared async connection, initializing it if needed."""
    global _db
    if _db is None:
        _db = await init_db()
    return _db


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


import atexit as _atexit
import asyncio as _asyncio_shutdown

def _emergency_close_db():
    """
    Called by atexit on any process exit — clean or not.
    Ensures the aiosqlite connection is closed and the
    database file handle is released before the process dies.
    This prevents 'database is locked' on the next startup.
    """
    global _db
    if _db is not None:
        try:
            loop = _asyncio_shutdown.new_event_loop()
            loop.run_until_complete(_db.close())
            loop.close()
        except Exception:
            pass
        finally:
            _db = None

_atexit.register(_emergency_close_db)

import signal as _signal_shutdown
import os as _os_shutdown

def _handle_sigterm(signum, frame):
    """
    Handle TaskKill /F and system shutdown signals.
    Closes DB before process is terminated.
    """
    _emergency_close_db()
    raise SystemExit(0)

# Only register on non-Windows or if not in a thread
# SIGTERM is not supported on Windows for Python
# but registering it is harmless on Windows
try:
    _signal_shutdown.signal(
        _signal_shutdown.SIGTERM,
        _handle_sigterm
    )
except (OSError, ValueError):
    pass  # Not in main thread or not supported
