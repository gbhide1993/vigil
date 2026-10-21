"""Tests for core/mcp_service.py's _derive_friction_findings() retry_loop
detection, specifically Task 4 of the P1 pilot sprint: Vigil's own
footprint (its own backend process spawning, its own install/data paths)
must not be flagged as agent friction, while an ordinary repeated-call
pattern on a real project path must still be caught. See conftest.py for
why VLAW_DATA_DIR is set there rather than here -- this module must only
ever touch that isolated temp DB, never the real dev DB in backend/data/."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

import db.database as database
from core.mcp_service import _derive_friction_findings


@pytest_asyncio.fixture
async def test_db():
    """Same pattern as tests/test_bugfixes.py::test_db -- fresh connection
    per test, explicitly closed on teardown."""
    database._db = None
    db = await database.get_db()
    yield db
    await database.close_db()


async def _make_agent(db, name: str) -> int:
    cur = await db.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)",
        (name, name),
    )
    await db.commit()
    return cur.lastrowid


async def _insert_retry_events(db, agent_id: int, session_id: str, event_type: str, path: str, count: int) -> None:
    """Inserts `count` events of the same type/path a minute apart, all
    well within the 10-minute retry_loop window."""
    base = datetime.now(timezone.utc)
    for i in range(count):
        ts = (base + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (?, ?, ?, ?, ?)",
            (agent_id, session_id, event_type, path, ts),
        )
    await db.commit()


def _uniq(label: str) -> str:
    return f"{label}_{uuid.uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_retry_loop_on_vigil_own_path_is_not_flagged(test_db):
    agent_id = await _make_agent(test_db, _uniq("claude_code_vigiltest"))
    session_id = _uniq("sess")

    await _insert_retry_events(
        test_db, agent_id, session_id, "proc_spawn",
        r"C:\Program Files\Vigil\backend\vigil-backend.exe", 5,
    )

    findings = await _derive_friction_findings(test_db, session_id=session_id)
    retry_findings = [f for f in findings if f["finding_type"] == "retry_loop"]
    assert retry_findings == []


@pytest.mark.asyncio
async def test_retry_loop_on_ordinary_project_path_is_still_flagged(test_db):
    agent_id = await _make_agent(test_db, _uniq("claude_code_realtest"))
    session_id = _uniq("sess")

    # Six identical spawns of one real tool: twice the 3-spawn threshold, so "high". (This used to be five spawns of
    # cmd.exe; cmd is a shell wrapper and is skipped now, see FRICTION_IGNORED_PROCESSES.)
    await _insert_retry_events(
        test_db, agent_id, session_id, "proc_spawn",
        r"C:\Users\dev\myproject\tools\build-step.exe", 6,
    )

    findings = await _derive_friction_findings(test_db, session_id=session_id)
    retry_findings = [f for f in findings if f["finding_type"] == "retry_loop"]
    assert len(retry_findings) == 1
    assert retry_findings[0]["confidence"] == "high"
    assert retry_findings[0]["session_id"] == session_id


# ------------------------------------------------------------------ retry_loop grouping, thresholds and exclusions
# Fixtures are shaped like the real database: git.exe with conhost.exe, Claude file-history checkpoint writes,
# project-file writes and a repeated command.

import json

import core.mcp_service as mcp_service


async def _insert(db, agent_id, session_id, event_type, path, seconds, detail=None):
    base = datetime.now(timezone.utc)
    for offset in seconds:
        ts = (base + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S")
        await db.execute(
            "INSERT INTO events (agent_id, session_id, event_type, path, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, session_id, event_type, path, json.dumps(detail) if detail is not None else None, ts),
        )
    await db.commit()


async def _setup(db, label):
    return await _make_agent(db, _uniq(label)), _uniq("sess")


def _retry(findings):
    return [f for f in findings if f["finding_type"] == "retry_loop"]


@pytest.mark.asyncio
async def test_git_and_conhost_three_times_each_produce_no_finding(test_db):
    agent_id, sid = await _setup(test_db, "friction_git")
    await _insert(test_db, agent_id, sid, "proc_spawn", "git.exe", [0, 1, 2], {"args": []})
    await _insert(test_db, agent_id, sid, "proc_spawn", "conhost.exe", [0, 1, 2], {"args": []})
    await _insert(test_db, agent_id, sid, "proc_spawn", r"\??\C:\Windows\system32\conhost.exe 0x4", [0, 1, 2, 3, 4, 5])
    await _insert(test_db, agent_id, sid, "proc_spawn", r"C:\Windows\system32\cmd.exe /d /s /c npx foo", [0, 1, 2, 3])
    assert _retry(await _derive_friction_findings(test_db, session_id=sid)) == []


@pytest.mark.asyncio
async def test_twenty_claude_file_history_writes_produce_no_finding(test_db):
    agent_id, sid = await _setup(test_db, "friction_cache")
    for i in range(20):
        await _insert(test_db, agent_id, sid, "file_write", rf"C:\Users\dev/.claude/file-history/abc\{i:016x}@v1", [i])
    await _insert(test_db, agent_id, sid, "file_write", r"C:\Users\dev\AppData\Local\Temp\claude-0056-cwd", [0, 1, 2, 3, 4, 5])
    await _insert(test_db, agent_id, sid, "file_write", r"C:\Windows\System32\config\systemprofile\AppData\x.dat", [0, 1, 2, 3, 4, 5])
    await _insert(test_db, agent_id, sid, "file_write", r"C:\Users\dev/.claude/shell-snapshots/snapshot-bash-1.sh", [0, 1, 2, 3, 4, 5])
    assert _retry(await _derive_friction_findings(test_db, session_id=sid)) == []


@pytest.mark.asyncio
async def test_five_writes_to_one_project_file_in_ten_minutes_produce_one_medium_finding(test_db):
    agent_id, sid = await _setup(test_db, "friction_file")
    path = r"C:\work\proj\src\app.py"
    await _insert(test_db, agent_id, sid, "file_write", path, [0, 60, 120, 180, 240])
    found = _retry(await _derive_friction_findings(test_db, session_id=sid))
    assert len(found) == 1
    assert found[0]["confidence"] == "medium" and found[0]["filepath"] == path and found[0]["session_id"] == sid
    assert found[0]["evidence"] == f"{path} file_write 5 times within 10 minutes"

    four_agent, four_sid = await _setup(test_db, "friction_file4")
    await _insert(test_db, four_agent, four_sid, "file_write", path, [0, 60, 120, 180])
    assert _retry(await _derive_friction_findings(test_db, session_id=four_sid)) == [], "4 writes is below the threshold"

    ten_agent, ten_sid = await _setup(test_db, "friction_file10")
    await _insert(test_db, ten_agent, ten_sid, "file_write", path, [i * 30 for i in range(10)])
    assert _retry(await _derive_friction_findings(test_db, session_id=ten_sid))[0]["confidence"] == "high"


@pytest.mark.asyncio
async def test_three_different_project_files_produce_no_finding(test_db):
    agent_id, sid = await _setup(test_db, "friction_diff")
    for name in ("a.py", "b.py", "c.py"):
        await _insert(test_db, agent_id, sid, "file_write", rf"C:\work\proj\src\{name}", [0, 60, 120])
    assert _retry(await _derive_friction_findings(test_db, session_id=sid)) == []


@pytest.mark.asyncio
async def test_the_same_command_spawned_three_times_produces_one_finding_and_different_commands_do_not(test_db):
    agent_id, sid = await _setup(test_db, "friction_cmd")
    cmd = r"C:\Python313\python.exe -m pytest tests/test_a.py"
    await _insert(test_db, agent_id, sid, "proc_spawn", cmd, [0, 30, 60], {"args": ["python.exe", "-m", "pytest", "tests/test_a.py"]})
    found = _retry(await _derive_friction_findings(test_db, session_id=sid))
    assert len(found) == 1 and found[0]["confidence"] == "medium"
    assert found[0]["evidence"] == f"{cmd} proc_spawn 3 times within 10 minutes"

    other_agent, other_sid = await _setup(test_db, "friction_cmd2")
    await _insert(test_db, other_agent, other_sid, "proc_spawn", "python.exe", [0, 30], {"args": ["python.exe", "a.py"]})
    await _insert(test_db, other_agent, other_sid, "proc_spawn", "python.exe", [40, 50], {"args": ["python.exe", "b.py"]})
    assert _retry(await _derive_friction_findings(test_db, session_id=other_sid)) == [], "two commands, two spawns each"


@pytest.mark.asyncio
async def test_session_abandoned_is_not_emitted_for_a_forty_minute_session(test_db, monkeypatch):
    agent_id, sid = await _setup(test_db, "friction_abandon")
    started = (datetime.now(timezone.utc) - timedelta(minutes=40)).strftime("%Y-%m-%d %H:%M:%S")
    await test_db.execute("INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, ?)", (sid, agent_id, started))
    await test_db.commit()
    findings = await _derive_friction_findings(test_db, session_id=sid)
    assert [f for f in findings if f["finding_type"] == "session_abandoned"] == []

    # the code is kept behind the switch
    assert mcp_service.EMIT_SESSION_ABANDONED is False
    monkeypatch.setattr(mcp_service, "EMIT_SESSION_ABANDONED", True)
    findings = await _derive_friction_findings(test_db, session_id=sid)
    assert [f["finding_type"] for f in findings if f["finding_type"] == "session_abandoned"] == ["session_abandoned"]


@pytest.mark.asyncio
async def test_rapid_revert_is_unchanged(test_db):
    agent_id, sid = await _setup(test_db, "friction_revert")
    await _insert(test_db, agent_id, sid, "file_write", r"C:\work\proj\src\x.py", [0, 30])
    found = [f for f in await _derive_friction_findings(test_db, session_id=sid) if f["finding_type"] == "rapid_revert"]
    assert len(found) == 1 and found[0]["confidence"] == "medium"


def test_the_thresholds_and_exclusion_lists_are_the_documented_ones():
    assert mcp_service.RETRY_THRESHOLD_FILE_WRITE == 5 and mcp_service.RETRY_THRESHOLD_PROC_SPAWN == 3
    assert mcp_service.RETRY_WINDOW_MINUTES == 10 and mcp_service.RETRY_HIGH_MULTIPLIER == 2
    for name in ("conhost", "git", "cmd", "powershell", "pwsh", "bash", "sh"):
        assert name in mcp_service.FRICTION_IGNORED_PROCESSES
    assert "claude" not in mcp_service.FRICTION_IGNORED_PROCESSES and "codex" not in mcp_service.FRICTION_IGNORED_PROCESSES
    for part in ("/.claude/file-history/", "shell-snapshots", "/systemprofile/"):
        assert part in mcp_service.FRICTION_IGNORED_PATH_PARTS
    assert mcp_service._is_ignored_friction_path(r"C:\x\claude-0056-cwd")
    assert not mcp_service._is_ignored_friction_path(r"C:\work\proj\src\app.py")
