"""SQLite connection manager. Single get_db() entry point used by the
rest of the backend — no other module should open its own connection."""

import json
import os
from pathlib import Path

import aiosqlite

DATA_DIR = Path(os.environ.get("VLAW_DATA_DIR", "./data"))
DB_PATH = DATA_DIR / "vlaw.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
POLICY_FILE = Path(os.environ.get("VLAW_POLICY_FILE", "./policy/vlaw-policy.json"))

_db: aiosqlite.Connection | None = None


async def init_db() -> aiosqlite.Connection:
    """Create the DB file, run schema.sql, and seed default policy.
    Safe to call on every startup — all statements are idempotent."""
    global _db

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    _db = await aiosqlite.connect(DB_PATH)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA foreign_keys = ON")

    schema_sql = SCHEMA_PATH.read_text()
    await _db.executescript(schema_sql)
    await _db.commit()

    await _seed_policy(_db)

    return _db


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
