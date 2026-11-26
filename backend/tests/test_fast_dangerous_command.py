"""A dangerous delete command in a REAL process, started under a fake agent parent, is found by the 1 s snapshot, read
in-process and raises its red line (the slow subprocess scan is not involved). The fake agent is a copy of cmd.exe named
claude.exe; the commands only touch a folder created inside pytest's own temp directory. See conftest.py for why
VLAW_DATA_DIR is set there."""

import asyncio
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
import pytest_asyncio

import db.database as database
from core import mass_delete
from core.aggregator import Aggregator
from core.attributor import Attributor
from watchers.process_watcher import ProcessWatcher

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="needs Windows processes")

GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    before = {}
    for table in ("agents", "alerts", "events"):
        cur = await conn.execute(f"SELECT COALESCE(MAX(id), 0) AS m FROM {table}")
        before[table] = (await cur.fetchone())["m"]
    cur = await conn.execute("SELECT id FROM sessions")
    sessions_before = {r["id"] for r in await cur.fetchall()}
    mass_delete.detector.reset()
    yield conn
    cur = await conn.execute("SELECT id FROM sessions")
    for r in await cur.fetchall():
        if r["id"] not in sessions_before:
            await conn.execute("DELETE FROM alerts WHERE session_id = ?", (r["id"],))
            await conn.execute("DELETE FROM events WHERE session_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (r["id"],))
            await conn.execute("DELETE FROM sessions WHERE id = ?", (r["id"],))
    await conn.execute("DELETE FROM alerts WHERE id > ?", (before["alerts"],))
    await conn.execute("DELETE FROM events WHERE id > ? AND id NOT IN (SELECT event_id FROM event_chain)", (before["events"],))
    await conn.execute("DELETE FROM agents WHERE id > ?", (before["agents"],))
    await conn.commit()
    mass_delete.detector.reset()
    await database.close_db()


def _commands(victim: Path):
    v = str(victim)
    cases = {
        "rd /s": f'cmd.exe /c "rd /s /q "{v}" & ping -n 4 127.0.0.1 >nul"',
        "del /s /f": f'cmd.exe /c "del /s /f /q "{v}\\*" & ping -n 4 127.0.0.1 >nul"',
        "Remove-Item -Recurse -Force": f'powershell.exe -NoProfile -Command "Remove-Item -Recurse -Force \'{v}\'; Start-Sleep 4"',
    }
    if GIT_BASH.exists():
        posix = "/" + v[0].lower() + v[2:].replace("\\", "/")
        cases["rm -rf"] = f'"{GIT_BASH}" -c "rm -rf \'{posix}\'; sleep 4"'
    return cases


def _case_names():
    return ["rd /s", "del /s /f", "Remove-Item -Recurse -Force", "rm -rf"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _case_names())
async def test_a_dangerous_delete_command_under_a_fake_agent_raises_its_red_line(db, tmp_path, case):
    commands = _commands(tmp_path / "victim")
    if case not in commands:
        pytest.skip("Git Bash is not installed")
    victim = tmp_path / "victim"
    victim.mkdir()
    for i in range(5):
        (victim / f"f{i}.txt").write_text("x")
    assert str(victim.resolve()).lower().startswith(str(tmp_path.resolve()).lower()), "the command only touches pytest's temp folder"

    fake_agent = tmp_path / "agent" / "claude.exe"
    fake_agent.parent.mkdir()
    shutil.copy(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", fake_agent)

    aggregator = Aggregator()
    aggregator._writer_task = asyncio.create_task(aggregator.start_writer())
    watcher = ProcessWatcher(Attributor(), aggregator)
    watcher._is_first_poll = False                 # the slow scan's baseline: everything running now is "already there"
    from watchers import fast_snapshot

    watcher._known_pids = set(fast_snapshot.snapshot())
    parent = subprocess.Popen([str(fake_agent), "/c", commands[case]], creationflags=subprocess.CREATE_NO_WINDOW,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    alert = None
    try:
        deadline = time.time() + 20
        while time.time() < deadline and alert is None:
            await watcher.fast_tick()
            cur = await db.execute("SELECT * FROM alerts WHERE reason = 'red_line_dangerous_command' AND id > 0")
            rows = await cur.fetchall()
            alert = rows[0] if rows else None
            await asyncio.sleep(0.25)
    finally:
        for child in psutil.Process(parent.pid).children(recursive=True) if parent.poll() is None else []:
            try:
                child.kill()
            except psutil.Error:
                pass
        parent.kill()
        await aggregator.stop_writer()

    assert alert is not None, f"no dangerous-command red line for {case}"
    assert alert["severity"] == "high" and alert["rule_type"] == "red_line"
    cur = await db.execute("SELECT detail, path FROM events WHERE event_type = 'proc_spawn' AND session_id IS NOT NULL ORDER BY id DESC")
    spawns = await cur.fetchall()
    assert any(case.split()[0].lower() in (s["path"] or "").lower() for s in spawns), [s["path"] for s in spawns]
