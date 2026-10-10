"""Performance gate: every endpoint polled unconditionally by the app
shell (App.jsx's /api/stats and /api/sessions, Sidebar.jsx's /api/agents
-- all three poll every 3s on every page, never unmounted) must answer
in under 250ms at p95 against a realistic data volume.

Seeds a synthetic DB sized to match today's live machine (~15k events,
~3k alerts, ~900 sessions, a handful of agents -- see the row counts
logged by the /api/stats investigation this gate exists to lock in)
rather than today's actual live DB, so this test is deterministic and
doesn't depend on whatever the real machine's data happens to look like
on any given run. See conftest.py for why VLAW_DATA_DIR is set there
rather than here."""

import statistics
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

import db.database as database
import main as main_module

P95_BUDGET_MS = 250
# 20 samples made p95 effectively "the 19th of 20 sorted values" -- a
# single slow outlier (GC pause, OS scheduler jitter) could swing the
# reported p95 by 150ms+ on this shared dev machine even though the
# median stayed consistently in the 80-160ms range across every run.
# 50 gives statistics.quantiles enough data for a stable tail estimate.
SAMPLES = 50

# Endpoint -> (method, path). All three are polled unconditionally by the
# app shell (see App.jsx and Sidebar.jsx) on a fixed 3s interval,
# regardless of which view is active.
APP_SHELL_POLLED_ENDPOINTS = {
    "/api/stats": ("GET", "/api/stats"),
    "/api/sessions": ("GET", "/api/sessions"),
    "/api/agents": ("GET", "/api/agents"),
}


@pytest_asyncio.fixture
async def seeded_db():
    """Same test_db pattern as the rest of this suite, seeded with a
    realistic row count before the test runs.

    This fixture is function-scoped and re-runs once per parametrized
    endpoint (3 times total), but VLAW_DATA_DIR points at the same
    on-disk file for the whole pytest process -- without clearing first,
    each run's INSERTs would stack on top of whatever the previous
    parametrized run already seeded (900 -> 1800 -> 2700 sessions by the
    third run), silently testing against 2-3x the intended row count and
    making the result depend on parametrize execution order rather than
    the fixed, documented size below. The DELETEs make every run start
    from the same clean slate regardless of what ran before it."""
    database._db = None
    db = await database.get_db()
    # Deletion order matters: event_chain.event_id and alerts.event_id both
    # reference events(id) with no ON DELETE CASCADE (PRAGMA foreign_keys
    # is ON -- see db/database.py), and events/alerts/sessions/baseline all
    # reference agents(id). test_evidence_chain.py runs earlier
    # alphabetically in the same shared DB file (see conftest.py) and
    # seals real events into event_chain, so deleting events before its
    # referencing rows fails with FOREIGN KEY constraint failed. baseline
    # must clear before agents for the same reason -- test_bugfixes.py's
    # resumed-session tests are the first in the suite to fold a real
    # session into core.baseline.Baseline (every pre-existing session
    # test uses a _NoopBaseline stub instead), so baseline rows
    # referencing those agents can now genuinely be left behind here too.
    for table in ("event_chain", "alerts", "events", "sessions", "baseline", "agents"):
        await db.execute(f"DELETE FROM {table}")
    await db.commit()

    now = datetime.now(timezone.utc)

    agent_ids = []
    for i in range(4):
        cur = await db.execute(
            "INSERT INTO agents (name, process_name, pid, approved, last_seen) "
            "VALUES (?, ?, NULL, 1, ?)",
            (f"perf_agent_{i}_{uuid.uuid4().hex[:6]}", "claude_code", now.strftime("%Y-%m-%d %H:%M:%S")),
        )
        agent_ids.append(cur.lastrowid)
    await db.commit()

    session_ids = []
    session_batch = []
    for i in range(900):
        sid = str(uuid.uuid4())
        session_ids.append(sid)
        started = now - timedelta(minutes=i * 3)
        session_batch.append((sid, agent_ids[i % len(agent_ids)], started.strftime("%Y-%m-%d %H:%M:%S")))
    await db.executemany(
        "INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, ?)",
        session_batch,
    )
    await db.commit()

    event_types = ["file_write", "file_read", "proc_spawn", "net_connect", "cred_access"]
    event_batch = []
    for i in range(15000):
        created = now - timedelta(minutes=i % 2880)  # spread across ~2 days
        event_batch.append((
            agent_ids[i % len(agent_ids)],
            session_ids[i % len(session_ids)],
            event_types[i % len(event_types)],
            f"/synthetic/path_{i}.py",
            created.strftime("%Y-%m-%d %H:%M:%S"),
        ))
        if len(event_batch) >= 5000:
            await db.executemany(
                "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, ?, ?, ?)",
                event_batch,
            )
            await db.commit()
            event_batch = []
    if event_batch:
        await db.executemany(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, ?, ?, ?)",
            event_batch,
        )
        await db.commit()

    alert_batch = []
    statuses = ["open", "open", "dismissed", "risk_accepted"]
    for i in range(3000):
        created = now - timedelta(minutes=i % 2880)
        alert_batch.append((
            agent_ids[i % len(agent_ids)],
            "medium",
            f"synthetic alert {i}",
            f"synthetic alert {i} description",
            statuses[i % len(statuses)],
            "policy",
            created.strftime("%Y-%m-%d %H:%M:%S"),
        ))
    await db.executemany(
        "INSERT INTO alerts (agent_id, severity, title, description, status, rule_type, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        alert_batch,
    )
    await db.commit()

    yield db
    await database.close_db()


def _p95(samples_ms):
    return statistics.quantiles(samples_ms, n=100)[94]


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint_name", list(APP_SHELL_POLLED_ENDPOINTS.keys()))
async def test_app_shell_endpoint_p95_under_budget(seeded_db, endpoint_name):
    method, path = APP_SHELL_POLLED_ENDPOINTS[endpoint_name]
    client = TestClient(main_module.app, base_url="http://localhost")

    samples_ms = []
    for _ in range(SAMPLES):
        if endpoint_name == "/api/stats":
            # Real polling is always >=3s apart (App.jsx's setInterval),
            # exceeding the 2s cache TTL, so every real poll does fresh
            # work -- force that here too, otherwise this tight sample
            # loop would mostly hit the cache and understate the actual
            # per-call cost the budget is meant to bound.
            main_module._stats_cache["computed_at"] = 0.0
        t0 = time.perf_counter()
        resp = client.request(method, path)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert resp.status_code == 200, f"{endpoint_name} returned {resp.status_code}: {resp.text[:200]}"
        samples_ms.append(elapsed_ms)

    p95 = _p95(samples_ms)
    print(
        f"\n{endpoint_name}: p95={p95:.1f}ms min={min(samples_ms):.1f}ms "
        f"max={max(samples_ms):.1f}ms median={statistics.median(samples_ms):.1f}ms"
    )
    assert p95 < P95_BUDGET_MS, (
        f"{endpoint_name} p95={p95:.1f}ms exceeds {P95_BUDGET_MS}ms budget "
        f"(samples: min={min(samples_ms):.1f}ms max={max(samples_ms):.1f}ms "
        f"median={statistics.median(samples_ms):.1f}ms)"
    )
