"""History search at the API level (a closed session found by any id prefix, all
of its events, paging) and the dashboard's local-day boundaries."""

import json
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest
import pytest_asyncio

import api.events as events_module
import core.runtime_state as runtime_state
import db.database as database
import main as main_module


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


async def _agent(db):
    name = f"hist_agent_{uuid.uuid4().hex[:8]}"
    cur = await db.execute("INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name))
    await db.commit()
    return cur.lastrowid, name


async def _session(db, agent_id, closed=True):
    sid = str(uuid.uuid4())
    await db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, '2026-10-12 03:00:00', ?)",
        (sid, agent_id, "2026-10-12 04:00:00" if closed else None),
    )
    return sid


async def _event(db, agent_id, sid, path, created, event_type="file_write", detail=None):
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (agent_id, sid, event_type, path, json.dumps(detail or {}), created),
    )


async def _cleanup(db, agent_id, *sids):
    await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
    for sid in sids:
        await db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    await db.commit()


async def _search(q, *, offset=0, limit=50):
    return await events_module.get_events(agent=None, type=None, since=None, session=None, q=q, offset=offset, limit=limit)


@pytest.mark.asyncio
async def test_closed_session_is_found_by_any_id_prefix_with_all_its_events(db):
    agent_id, _ = await _agent(db)
    old = await _session(db, agent_id)
    newer = await _session(db, agent_id, closed=False)
    for i in range(120):
        await _event(db, agent_id, old, f"C:/p/old{i}.py", f"2026-10-12 03:{i // 60:02d}:{i % 60:02d}")
    for i in range(60):    # 60 newer events from another session push the old one out of "the latest 50"
        await _event(db, agent_id, newer, f"C:/p/new{i}.py", f"2026-10-12 05:00:{i:02d}")
    await db.commit()
    try:
        latest = (await events_module.get_events(agent=None, type=None, since=None, session=None, q=None, offset=0, limit=50))["events"]
        assert old not in {e["session_id"] for e in latest}, "the bug: a plain latest-50 view never contains the old session"
        for q in (old[:8], old[:8].upper(), old[:1], old[:20], old, old.upper(), f"  {old[:8]}  "):
            result = await _search(q)
            sessions = {s["session_id"] for s in result["sessions"]}
            assert old in sessions, q
            assert len(result["events"]) == 50 and result["total"] >= 120
        result = await _search(old[:12])
        assert result["total"] == 120 and result["session_count"] == 1 and result["sessions"][0]["session_id"] == old
        assert result["sessions"][0]["matching_events"] == 120
        assert result["sessions"][0]["agent_name"] and result["sessions"][0]["ended_at"] == "2026-10-12 04:00:00"
        seen = [e["id"] for e in result["events"]]
        for offset in (50, 100):
            page = await _search(old[:12], offset=offset)
            seen += [e["id"] for e in page["events"]]
        assert len(seen) == 120 and len(set(seen)) == 120, "paging walks every event of the session once"
        ordered = (await _search(old[:12], limit=120))["events"]
        assert [e["created_at"] for e in ordered] == sorted((e["created_at"] for e in ordered), reverse=True)
    finally:
        await _cleanup(db, agent_id, old, newer)


@pytest.mark.asyncio
async def test_id_search_is_a_prefix_match_not_a_substring_match(db):
    agent_id, _ = await _agent(db)
    sid = await _session(db, agent_id)
    await _event(db, agent_id, sid, "C:/p/a.py", "2026-10-12 03:00:00")
    await db.commit()
    try:
        assert sid not in {s["session_id"] for s in (await _search(sid[1:9]))["sessions"]}
        assert sid in {s["session_id"] for s in (await _search(sid[:9]))["sessions"]}
    finally:
        await _cleanup(db, agent_id, sid)


@pytest.mark.asyncio
async def test_text_search_covers_agent_type_path_and_detail_and_escapes_wildcards(db):
    agent_id, name = await _agent(db)
    sid = await _session(db, agent_id)
    await _event(db, agent_id, sid, "C:/p/100%_done.txt", "2026-10-12 03:00:01")
    await _event(db, agent_id, sid, "C:/p/plain.txt", "2026-10-12 03:00:02", detail={"note": "zebrafinch-marker"})
    await _event(db, agent_id, sid, "curl http://x", "2026-10-12 03:00:03", event_type="proc_spawn")
    await db.commit()
    try:
        assert (await _search("100%_done"))["total"] == 1
        assert (await _search("%_"))["total"] == 1, "% and _ are literal characters, not wildcards"
        assert (await _search("zebrafinch-marker"))["total"] == 1
        assert (await _search(name))["total"] == 3
        assert (await _search("PROC_SPAWN"))["total"] >= 1
        assert (await _search("no-such-text-" + uuid.uuid4().hex))["total"] == 0
    finally:
        await _cleanup(db, agent_id, sid)


@pytest.mark.asyncio
async def test_session_without_event_rows_is_still_found_by_id_and_plain_listing_is_unchanged(db):
    agent_id, _ = await _agent(db)
    sid = await _session(db, agent_id)
    await db.commit()
    try:
        result = await _search(sid[:8])
        assert result["total"] == 0 and [s["session_id"] for s in result["sessions"]] == [sid]
        plain = await events_module.get_events(agent=None, type=None, since=None, session=None, q=None, offset=0, limit=5)
        assert set(plain) == {"events"}, "without q the reply keeps its old shape"
    finally:
        await _cleanup(db, agent_id, sid)


# ------------------------------------------------ dashboard day boundaries

IST = ZoneInfo("Asia/Kolkata")


class _FixedDatetime(datetime):
    _fixed = None

    @classmethod
    def now(cls, tz=None):
        return cls._fixed.astimezone(tz) if tz is not None else cls._fixed


@pytest.fixture
def ist_at_2am(monkeypatch):
    """02:00 IST on 7 Oct = 20:30 UTC on 6 Oct: the UTC date and the local date disagree."""
    import api.export as export_module
    import core.local_day as local_day

    _FixedDatetime._fixed = datetime(2026, 10, 7, 2, 0, 0, tzinfo=IST)
    monkeypatch.setattr(local_day, "local_tz", lambda: IST)
    monkeypatch.setattr(export_module, "datetime", _FixedDatetime)
    runtime_state.stats_cache["data"] = None
    yield
    runtime_state.stats_cache["data"] = None


async def _stats():
    runtime_state.stats_cache["data"] = None
    return await main_module.get_stats()


async def _alert(db, agent_id, created, status="open", resolved=None):
    await db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, rule_type, status, created_at, resolved_at)"
        " VALUES (?, 'low', 't', 'd', 'policy', ?, ?, ?)",
        (agent_id, status, created, resolved),
    )


def test_local_day_window_is_the_local_calendar_day_in_utc(ist_at_2am):
    from core.local_day import local_day_window

    assert local_day_window(0) == ("2026-10-06 18:30:00", "2026-10-07 18:30:00")
    assert local_day_window(1) == ("2026-10-05 18:30:00", "2026-10-06 18:30:00")


@pytest.mark.asyncio
async def test_stats_today_and_yesterday_use_the_local_day_not_the_utc_day(db, ist_at_2am):
    agent_id, _ = await _agent(db)
    sid = await _session(db, agent_id)
    await db.execute("UPDATE sessions SET started_at = '2026-10-06 19:00:00' WHERE id = ?", (sid,))
    before = await _stats()
    # 19:00 UTC on 6 Oct is 00:30 IST on 7 Oct: local today, UTC yesterday.
    await _event(db, agent_id, sid, "C:/p/a", "2026-10-06 19:00:00")
    await _event(db, agent_id, sid, "C:/p/b", "2026-10-07 10:00:00", event_type="cred_access")
    # 18:29:59 UTC on 6 Oct is 23:59:59 IST on 6 Oct: local yesterday.
    await _event(db, agent_id, sid, "C:/p/c", "2026-10-06 18:29:59")
    await _event(db, agent_id, sid, "C:/p/d", "2026-10-06 10:00:00", event_type="cred_access")
    await _event(db, agent_id, sid, "C:/p/e", "2026-10-07 18:30:00")          # first instant of local tomorrow
    await _alert(db, agent_id, "2026-10-06 19:00:00")                          # local today
    await _alert(db, agent_id, "2026-10-06 18:00:00")                          # local yesterday
    await db.commit()
    try:
        after = await _stats()
        assert after["events_today"] - before["events_today"] == 2
        assert after["events_yesterday"] - before["events_yesterday"] == 2
        assert after["cred_accesses_today"] - before["cred_accesses_today"] == 1
        assert after["cred_accesses_yesterday"] - before["cred_accesses_yesterday"] == 1
        assert after["sessions_today"] - before["sessions_today"] == 1
        assert after["alerts_today"] - before["alerts_today"] == 1
    finally:
        await db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await _cleanup(db, agent_id, sid)


@pytest.mark.asyncio
async def test_alerts_open_yesterday_is_the_number_open_at_local_midnight(db, ist_at_2am):
    agent_id, _ = await _agent(db)
    before = await _stats()
    await _alert(db, agent_id, "2026-10-06 10:00:00")                                               # open before and now: counts
    await _alert(db, agent_id, "2026-10-06 10:00:00", "resolved", "2026-10-06 12:00:00")             # resolved before midnight
    await _alert(db, agent_id, "2026-10-06 10:00:00", "dismissed", "2026-10-06 20:00:00")            # resolved after midnight: counts
    await _alert(db, agent_id, "2026-10-06 19:00:00")                                               # created after midnight
    await _alert(db, agent_id, "2026-10-06 10:00:00", "resolved", None)                              # closed, time unknown: not counted
    await db.commit()
    try:
        after = await _stats()
        assert after["alerts_open_yesterday"] - before["alerts_open_yesterday"] == 2
        assert after["alerts_open"] - before["alerts_open"] == 2     # the open one and the one created after midnight
    finally:
        await db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
        await _cleanup(db, agent_id)


def test_stats_no_longer_computes_utc_day_bounds():
    import inspect

    source = inspect.getsource(main_module.get_stats)
    assert "datetime.now(timezone.utc)" not in source and "local_day_window" in source
