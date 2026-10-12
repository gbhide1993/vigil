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
    Safe to call on every startup — all statements are idempotent.

    Builds and fully configures the connection in a local variable, and
    only publishes it to the module-level _db as the very last step.
    Publishing early (the previous shape: `_db = await aiosqlite.connect(...)`
    followed by several more awaited setup steps before row_factory and the
    rest were in place) left a real window where a concurrent get_db()
    caller could observe a non-None _db that wasn't fully configured yet --
    e.g. row_factory not set yet, so `row["col"]` raises TypeError: tuple
    indices must be integers or slices, not str. Harmless while init_db()
    only ever ran once at cold startup before any concurrent traffic
    existed; reachable for real once replace_db() started re-running this
    while the app is live and busy."""
    global _db

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    conn = await aiosqlite.connect(DB_PATH)
    await conn.execute("PRAGMA busy_timeout = 5000")
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA wal_autocheckpoint = 0")
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")

    schema_sql = SCHEMA_PATH.read_text()
    await conn.executescript(schema_sql)
    await conn.commit()

    cur = await conn.execute("PRAGMA user_version")
    current_version = (await cur.fetchone())[0]
    if current_version < SCHEMA_VERSION:
        await conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        await conn.commit()
        logger.info("schema version updated %d -> %d", current_version, SCHEMA_VERSION)

    await _migrate(conn)
    await _seed_policy(conn)

    _db = conn  # publish only now that every setup step above has completed
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
    if "reason" not in columns:
        await db.execute("ALTER TABLE alerts ADD COLUMN reason TEXT")
        await db.commit()
    if "target" not in columns:
        await db.execute("ALTER TABLE alerts ADD COLUMN target TEXT")
        await db.commit()

    cur = await db.execute("PRAGMA table_info(sessions)")
    columns = {row["name"] for row in await cur.fetchall()}
    if "summary" not in columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN summary TEXT")
        await db.commit()

    cur = await db.execute("PRAGMA table_info(events)")
    columns = {row["name"] for row in await cur.fetchall()}
    if "pid" not in columns:
        # Lets core.behaviour_detector.get_recent_events_for_pid look up an
        # unknown process's own recent activity directly, instead of only
        # through the agent_id it doesn't have yet.
        await db.execute("ALTER TABLE events ADD COLUMN pid INTEGER")
        await db.commit()
    if "behaviour_score" not in columns:
        await db.execute("ALTER TABLE events ADD COLUMN behaviour_score REAL DEFAULT NULL")
        await db.commit()
    if "event_source" not in columns:
        # 'etw' | 'realtime_heuristic' | 'poll' -- which file-watching tier
        # produced this row (see watchers/file_watcher.py's module docstring).
        await db.execute("ALTER TABLE events ADD COLUMN event_source TEXT DEFAULT NULL")
        await db.commit()

    cur = await db.execute("PRAGMA table_info(sessions)")
    columns = {row["name"] for row in await cur.fetchall()}
    if "operator_username" not in columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN operator_username TEXT")
        await db.commit()
    if "operator_hostname" not in columns:
        await db.execute("ALTER TABLE sessions ADD COLUMN operator_hostname TEXT")
        await db.commit()
    if "resumed" not in columns:
        # SQLite's ALTER TABLE ... ADD COLUMN requires a constant default,
        # not CURRENT_TIMESTAMP-style magic -- 0 is correct here anyway:
        # every session that already existed before this column was added
        # was opened under the pre-fix touch(), which never passed
        # resumed=True, so treating pre-existing rows as "not resumed" is
        # accurate, not just a safe default.
        await db.execute("ALTER TABLE sessions ADD COLUMN resumed INTEGER NOT NULL DEFAULT 0")
        await db.commit()


async def _seed_policy(db: aiosqlite.Connection) -> None:
    if not POLICY_FILE.exists():
        return

    # utf-8-sig strips a leading UTF-8 BOM if present (and behaves exactly
    # like utf-8 if it isn't) -- a BOM here previously made json.loads
    # raise on the stray ﻿ character before the opening brace, which
    # blocked init_db() and therefore the whole backend from starting.
    # Any other corruption (truncated file, not a JSON object at all) is
    # treated the same way: log it and seed nothing this run rather than
    # crash startup, exactly as if POLICY_FILE didn't exist -- whatever
    # policy rows already exist in the DB, or the built-in defaults
    # elsewhere, still apply.
    try:
        policy = json.loads(POLICY_FILE.read_text(encoding="utf-8-sig"))
        if not isinstance(policy, dict):
            raise ValueError(f"expected a JSON object at the top level, got {type(policy).__name__}")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        logger.warning("policy file %s is invalid (%s) -- falling back to defaults", POLICY_FILE, e)
        return

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


async def replace_db() -> aiosqlite.Connection:
    """Abandons the current shared connection and opens a fresh one in
    its place. For use only when the current connection is confirmed
    wedged (see core.aggregator's write watchdog) -- aiosqlite.Connection
    is itself a background Thread processing one queued operation at a
    time; if that thread is permanently stuck inside a single slow/hung
    SQLite call, nothing queued behind it (on this connection) will ever
    complete, and there is no way to forcibly stop a Python thread.

    Deliberately does NOT call close() on the old connection first --
    close() just queues `self._conn.close` onto the same stuck
    background thread (see aiosqlite's Connection.close()) and would
    hang exactly the same way. The old connection (and its thread) is
    simply abandoned; the thread leaks until process exit, which is
    cheap and acceptable next to a permanently wedged backend.

    Every future get_db() call -- from Aggregator's writer, from
    ProcessWatcher's direct writes, from any HTTP handler -- sees the new
    connection from this point on. get_read_db() is unaffected: it never
    shares state with this singleton in the first place.

    Publishing here is just `_db = None` followed by delegating entirely
    to init_db(), which (see its docstring) now only publishes _db as its
    own last step once the new connection is fully configured -- so
    nothing this function does exposes a partially-set-up connection to
    another caller either. The `_db = None` window itself just means a
    concurrent get_db() call during that window would race to build its
    own connection via init_db() too; whichever finishes last wins and
    becomes the final _db, the other is harmlessly discarded (leaked,
    same as the old wedged connection) -- rare (this only runs after a
    confirmed wedge) and never produces a broken/partial connection for
    either caller, just a wasted extra connect on the rare unlucky
    overlap."""
    global _db
    _db = None
    return await init_db()


async def close_db() -> None:
    global _db
    if _db is not None:
        await _db.close()
        _db = None


async def get_read_db() -> aiosqlite.Connection:
    """
    Short-lived read-only connection for API handlers.
    Opens fresh, reads, caller must close.
    Never shares state with the Aggregator writer.
    PRAGMA query_only prevents accidental writes.
    """
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA busy_timeout = 5000")
    await db.execute("PRAGMA query_only = ON")
    return db


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
