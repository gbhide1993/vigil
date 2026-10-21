"""Pilot-readiness fixes: the "What this report covers" block (identical in the daily PDF, the
per-session PDF and the JSON), the installer manifest, and the .gitignore entries."""

import json
import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio

import api.export as export_module
import db.database as database
from core import report_coverage

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "installer"

# The facts the block must state, word for word (the wording is a product decision, not a detail).
REQUIRED = [
    "File writes and deletes and process spawns are recorded.",
    "File reads are not recorded.",
    "Network and MCP calls are not monitored in this version.",
    "Attribution to an agent is a best guess, based on file location and which agents are running.",
    "Generated folders (node_modules, .venv, dist, build) are ignored.",
    "Records stay on this machine.",
]


def normal(text: str) -> str:
    return " ".join(text.split())


def test_the_block_states_exactly_the_required_facts_and_the_read_limit():
    assert report_coverage.TITLE == "What this report covers"
    assert report_coverage.LINES[:6] == REQUIRED
    last = report_coverage.LINES[6]
    assert "reading one is not detected" in last and "cannot fire" in last, "A2: the read-based Red Lines cannot fire"
    for word in ("tamper", "cannot be altered"):
        assert word not in " ".join(report_coverage.LINES).lower()


# ------------------------------------------------------------------ the three outputs

def _capture_pdf(client, path):
    from reportlab.pdfgen import canvas

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture):
        response = client.get(path)
    assert response.status_code == 200
    return normal(" ".join(drawn))


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    conn = await database.get_db()
    yield conn
    await database.close_db()


@pytest.mark.asyncio
async def test_the_block_is_identical_in_the_daily_pdf_the_session_pdf_and_the_json(db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.sessions as sessions_module

    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"cov_{uuid.uuid4().hex[:8]}",))
    agent_id = cur.lastrowid
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", (sid, agent_id))
    await db.execute("INSERT INTO events (agent_id, session_id, event_type, path) VALUES (?, ?, 'file_write', '/tmp/x.py')", (agent_id, sid))
    await db.commit()
    app = FastAPI()
    app.include_router(export_module.router)
    app.include_router(sessions_module.router)
    client = TestClient(app)
    try:
        daily_pdf = _capture_pdf(client, "/export/pdf")
        session_pdf = _capture_pdf(client, f"/sessions/{sid}/report")
        daily_json = client.get("/export/json").json()
        session_json = client.get(f"/sessions/{sid}/report/preview").json()
    finally:
        await db.execute("DELETE FROM events WHERE agent_id = ? AND id NOT IN (SELECT event_id FROM event_chain)", (agent_id,))
        await db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        await db.commit()

    expected = {"title": report_coverage.TITLE, "lines": report_coverage.LINES}
    assert daily_json["what_this_report_covers"] == expected
    assert session_json["what_this_report_covers"] == expected
    for text in (daily_pdf, session_pdf):
        assert report_coverage.TITLE in text
        for line in report_coverage.LINES:
            assert normal(line) in text, line
        # the lines come in the same order in both PDFs
        positions = [text.index(normal(line)) for line in report_coverage.LINES]
        assert positions == sorted(positions)


@pytest.mark.asyncio
async def test_the_block_is_near_the_top_of_both_pdfs(db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.sessions as sessions_module

    cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"covtop_{uuid.uuid4().hex[:8]}",))
    sid = str(uuid.uuid4())
    await db.execute("INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", (sid, cur.lastrowid))
    await db.commit()
    app = FastAPI()
    app.include_router(export_module.router)
    app.include_router(sessions_module.router)
    client = TestClient(app)
    try:
        daily = _capture_pdf(client, "/export/pdf")
        session = _capture_pdf(client, f"/sessions/{sid}/report")
    finally:
        await db.execute("DELETE FROM sessions WHERE id = ?", (sid,))
        await db.commit()
    assert daily.index("Vigil Audit Report") < daily.index(report_coverage.TITLE) < 2500, "near the top of the daily PDF"
    assert session.index("Generated:") < session.index(report_coverage.TITLE) < session.index("File changes ("), "before the file list"


# ------------------------------------------------------------------ manifest

def _node(*args):
    return subprocess.run(["node", str(INSTALLER / "manifest.js"), *map(str, args)], capture_output=True, text=True, timeout=60)


@pytest.fixture
def built(tmp_path):
    installer = tmp_path / "Vigil-Setup-0.9.0.exe"
    installer.write_bytes(b"MZ" + b"installer bytes " * 1000)
    manifest = tmp_path / "manifest.json"
    result = _node("write", installer, "0.9.0", manifest)
    assert result.returncode == 0, result.stderr
    return installer, manifest


def test_the_manifest_has_what_the_extension_reads(built):
    import hashlib

    installer, manifest = built
    data = json.loads(manifest.read_text(encoding="utf-8"))
    asset = data["win_x64"]
    assert data["version"] == "0.9.0" and data["released"]
    assert asset["url"] == "https://download.getvvault.com/Vigil-Setup-0.9.0.exe"
    assert asset["sha256"] == hashlib.sha256(installer.read_bytes()).hexdigest()
    assert asset["size_bytes"] == installer.stat().st_size
    # the extension refuses a manifest without these two (vigil-vscode/src/backendManager.ts readManifest)
    source = (ROOT / "vigil-vscode" / "src" / "backendManager.ts").read_text(encoding="utf-8")
    assert "manifest['win_x64']" in source and "asset.url" in source and "asset.sha256" in source
    assert _node("check", manifest, installer, "0.9.0").returncode == 0


def test_the_check_fails_when_the_installer_differs_from_the_manifest(built):
    installer, manifest = built
    installer.write_bytes(installer.read_bytes() + b"x")
    result = _node("check", manifest, installer, "0.9.0")
    assert result.returncode == 1 and "BUILD FAILED" in result.stderr and "is not the installer's hash" in result.stderr


def test_the_check_fails_on_a_version_mismatch(built):
    installer, manifest = built
    result = _node("check", manifest, installer, "0.9.1")
    assert result.returncode == 1 and "differs from the build version" in result.stderr


def test_the_check_fails_on_a_wrong_host_a_wrong_name_or_a_missing_hash(built):
    installer, manifest = built
    data = json.loads(manifest.read_text(encoding="utf-8"))
    for mutate, message in (
        (lambda d: d["win_x64"].update(url="https://evil.example.com/Vigil-Setup-0.9.0.exe"), "must be https on download.getvvault.com"),
        (lambda d: d["win_x64"].update(url="http://download.getvvault.com/Vigil-Setup-0.9.0.exe"), "must be https on download.getvvault.com"),
        (lambda d: d["win_x64"].update(url="https://download.getvvault.com/Other.exe"), "does not end with the installer name"),
        (lambda d: d["win_x64"].update(sha256=""), "needs both"),
    ):
        changed = json.loads(json.dumps(data))
        mutate(changed)
        broken = manifest.with_name("broken.json")
        broken.write_text(json.dumps(changed), encoding="utf-8")
        result = _node("check", broken, installer, "0.9.0")
        assert result.returncode == 1 and message in result.stderr, (message, result.stderr)


def test_the_stale_manifest_of_an_old_build_is_refused():
    """The 0.2.10 manifest in installer/output has an empty sha256: the extension cannot use it."""
    stale = INSTALLER / "output" / "manifest.json"
    if not stale.exists():
        pytest.skip("no manifest in installer/output on this machine")
    data = json.loads(stale.read_text(encoding="utf-8"))
    if data["win_x64"].get("sha256"):
        pytest.skip("the manifest in installer/output is a current one")
    assert _node("check", stale, INSTALLER / "output" / "Vigil-Setup-0.9.0.exe", "0.9.0").returncode == 1


def test_build_bat_writes_and_checks_the_manifest_after_the_installer_hash():
    bat = (INSTALLER / "build.bat").read_text(encoding="utf-8")
    order = [bat.index(token) for token in (".sha256", "manifest.js write", "manifest.js check", "Done.")]
    assert order == sorted(order)
    write_block = bat[bat.index("manifest.js write"):bat.index("manifest.js check")]
    assert "if errorlevel 1 goto error" in write_block
    check_block = bat[bat.index("manifest.js check"):bat.index("echo Done.")]
    assert "if errorlevel 1 goto error" in check_block
    assert "check-version.js" in bat and bat.index("check-version.js") < bat.index("pyinstaller.exe"), "the version check stays first"
    assert "upload" not in bat.lower().replace("nothing is uploaded", "")


# ------------------------------------------------------------------ .gitignore

def test_gitignore_covers_rotated_logs_and_the_dev_key_directory():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for entry in ("backend/*.log*", "*.log.[0-9]*", "backend/keys/"):
        assert entry in text.splitlines(), entry
    tracked = subprocess.run(["git", "ls-files", "--", "*/keys/*", "keys/*", "backend/*.log*"], cwd=ROOT, capture_output=True, text=True).stdout
    assert tracked.strip() == "", "nothing tracked is hidden by the new entries"
