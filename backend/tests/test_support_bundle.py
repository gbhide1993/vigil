"""The support bundle holds only allow-listed entries and nothing from the database."""

import io
from pathlib import Path
import json
import types
import uuid
import zipfile

import pytest
import pytest_asyncio
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import api.support as support
import core.runtime_state as runtime_state
import db.database as database

SENTINELS = ("SENTINEL_EVENT_PATH", "SENTINEL_ALERT_TEXT", "SENTINEL_COMMAND_LINE", "SENTINEL_LICENSE_KEY", "SENTINEL_POLICY_SECRET")


@pytest_asyncio.fixture
async def seeded_db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    db = await database.get_db()
    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"bundle_agent_{uuid.uuid4().hex[:6]}",))
    agent_id = cur.lastrowid
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at) VALUES (?, ?, CURRENT_TIMESTAMP)", (sid, agent_id))
    await db.execute(
        "INSERT INTO events (agent_id, session_id, event_type, path, detail) VALUES (?, ?, 'proc_spawn', ?, ?)",
        (agent_id, sid, "SENTINEL_EVENT_PATH curl SENTINEL_COMMAND_LINE", '{"command": "SENTINEL_COMMAND_LINE"}'),
    )
    await db.execute(
        "INSERT INTO alerts (agent_id, severity, title, description, rule_type) VALUES (?, 'high', 'SENTINEL_ALERT_TEXT', 'SENTINEL_ALERT_TEXT', 'policy')",
        (agent_id,),
    )
    await db.commit()
    yield db
    await db.execute("DELETE FROM alerts WHERE agent_id = ?", (agent_id,))
    await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
    await db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
    await db.commit()
    await database.close_db()


@pytest.fixture
def client_and_files(tmp_path, monkeypatch):
    log = tmp_path / "logs" / "vlaw-backend.log"
    log.parent.mkdir()
    log.write_text("main log line\n", encoding="utf-8")
    (log.parent / "vlaw-backend.log.1").write_text("rotated one\n", encoding="utf-8")
    (log.parent / "vlaw-backend.log.2").write_text("rotated two\n", encoding="utf-8")
    # Neighbours of the log that must never be picked up.
    (log.parent / "vlaw.db").write_bytes(b"SQLite format 3 SENTINEL_EVENT_PATH")
    (log.parent / ".vlaw-license").write_text("SENTINEL_LICENSE_KEY", encoding="utf-8")
    (log.parent / "vlaw-policy.json").write_text('{"secret": "SENTINEL_POLICY_SECRET"}', encoding="utf-8")
    (log.parent / "vlaw-backend.logger.txt").write_text("not a rotated copy", encoding="utf-8")

    async def fake_health():
        return {"status": "ok", "version": "0.9.0", "file_watcher_alive": True}

    async def fake_scope(_db):
        return ["C:/work/project one"]

    monkeypatch.setitem(runtime_state.state, "log_path", str(log))
    monkeypatch.setitem(runtime_state.state, "version", "0.9.0")
    monkeypatch.setitem(runtime_state.state, "health_fn", fake_health)
    monkeypatch.setitem(runtime_state.state, "observer", None)
    monkeypatch.setattr(support, "get_scope_directories", fake_scope)
    app = FastAPI()
    app.include_router(support.router, prefix="/api")
    return TestClient(app)


def _zip(response):
    assert response.status_code == 200 and response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"].startswith('attachment; filename="vigil-support-')
    return zipfile.ZipFile(io.BytesIO(response.content))


@pytest.mark.asyncio
async def test_bundle_has_exactly_the_allowed_entries_and_nothing_from_the_database(seeded_db, client_and_files):
    archive = _zip(client_and_files.post("/api/support/bundle"))
    names = sorted(archive.namelist())
    assert names == sorted([
        "README.txt", "health.json", "build-info.json", "monitoring-status.txt", "watched-folders.txt",
        "logs/vlaw-backend.log", "logs/vlaw-backend.log.1", "logs/vlaw-backend.log.2",
    ])
    assert set(support.BUNDLE_ENTRIES) <= set(names)
    everything = b"".join(archive.read(n) for n in names).decode("utf-8", errors="replace")
    for sentinel in SENTINELS:
        assert sentinel not in everything, sentinel
    assert "SQLite format" not in everything
    assert json.loads(archive.read("health.json"))["status"] == "ok"
    assert json.loads(archive.read("build-info.json"))["version"] == "0.9.0"
    status = archive.read("monitoring-status.txt").decode()
    assert "network_monitoring:" in status and "file_watcher_tier:" in status and "Coverage notes" in status
    assert "C:/work/project one" in archive.read("watched-folders.txt").decode()
    assert archive.read("logs/vlaw-backend.log").decode().strip() == "main log line"


@pytest.mark.asyncio
async def test_bundle_is_still_made_when_health_fails_and_there_are_no_logs(seeded_db, client_and_files, monkeypatch):
    async def broken():
        raise RuntimeError("database is locked with SENTINEL_EVENT_PATH")

    monkeypatch.setitem(runtime_state.state, "health_fn", broken)
    monkeypatch.setitem(runtime_state.state, "log_path", None)
    archive = _zip(client_and_files.post("/api/support/bundle"))
    assert sorted(archive.namelist()) == sorted(support.BUNDLE_ENTRIES)
    health = json.loads(archive.read("health.json"))
    assert health == {"error": "health check failed: RuntimeError"}, "the error text is not copied into the bundle"


def test_contents_endpoint_lists_what_is_and_is_not_included(client_and_files):
    data = client_and_files.get("/api/support/contents").json()
    assert any("log" in line.lower() for line in data["included"])
    assert any("database" in line.lower() for line in data["excluded"])
    assert any("license" in line.lower() for line in data["excluded"])


def test_only_loopback_clients_may_ask_for_the_bundle():
    request = types.SimpleNamespace(client=types.SimpleNamespace(host="203.0.113.7"))
    with pytest.raises(HTTPException) as caught:
        support._require_loopback(request)
    assert caught.value.status_code == 403
    support._require_loopback(types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1")))


def test_the_real_app_serves_the_endpoints_and_the_host_guard_still_applies():
    import main as main_module

    paths = {route.path for route in main_module.app.routes}
    assert "/api/support/bundle" in paths and "/api/support/contents" in paths
    assert runtime_state.state.get("health_fn") is main_module.health
    client = TestClient(main_module.app, base_url="http://evil.example")
    assert client.post("/api/support/bundle").status_code == 403, "DNS-rebinding style host is refused"


# ------------------------------------------------------------------ only the end of each log

@pytest.mark.asyncio
async def test_a_large_log_is_cut_to_its_last_5_mb_at_a_line_boundary(seeded_db, client_and_files):
    log = Path(runtime_state.state["log_path"])
    line = "2026-10-14 10:00:00,000 INFO a log line of a typical length for the backend, number "
    count = 90_000                      # about 7.9 MB
    with open(log, "w", encoding="utf-8", newline="\n") as fh:
        for i in range(count):
            fh.write(f"{line}{i}\n")
    assert log.stat().st_size > support.LOG_TAIL_BYTES

    archive = _zip(client_and_files.post("/api/support/bundle"))
    data = archive.read("logs/vlaw-backend.log")
    assert len(data) <= support.LOG_TAIL_BYTES + 300, "at most 5 MB plus the one-line notice"
    lines = data.decode("utf-8").split("\n")
    assert lines[0].startswith("[Vigil support bundle: the first ") and "bytes of this log were left out" in lines[0]
    assert lines[1].startswith(line), "cut at a line boundary: the first kept line is whole"
    assert lines[-2] == f"{line}{count - 1}", "the end of the log is what is kept"

    readme = archive.read("README.txt").decode()
    assert "last 5 MB of the Vigil log file and of each rotated copy" in readme
    assert "last 5 MB" in readme


@pytest.mark.asyncio
async def test_small_logs_are_included_whole_and_the_contents_list_says_5_mb(seeded_db, client_and_files):
    archive = _zip(client_and_files.post("/api/support/bundle"))
    assert archive.read("logs/vlaw-backend.log.1").decode().strip() == "rotated one"
    assert not archive.read("logs/vlaw-backend.log").decode().startswith("[Vigil support bundle")
    included = client_and_files.get("/api/support/contents").json()["included"]
    assert any("last 5 MB" in entry for entry in included)
