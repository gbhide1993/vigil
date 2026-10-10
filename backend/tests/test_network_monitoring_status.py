"""Network monitoring is deliberately off (see the comment above the disabled
network_watcher job in main.py). These tests cover the honest reporting of
that: the status is read from real scheduler state, the report/JSON/health
say "off" (and flip to "on" when the watcher's job is registered), and no
report text claims network visibility. See conftest.py for why VLAW_DATA_DIR
is set there rather than here."""

import re
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio

import api.export as export_module
import core.monitoring_status as monitoring_status
import db.database as database
from core.monitoring_status import NETWORK_WATCHER_JOB_ID, bind_scheduler, network_monitoring


class _FakeScheduler:
    def __init__(self, running=True, job_ids=()):
        self.running = running
        self._job_ids = set(job_ids)

    def get_job(self, job_id):
        return object() if job_id in self._job_ids else None


@pytest.fixture(autouse=True)
def _unbind_scheduler():
    bind_scheduler(None)
    yield
    bind_scheduler(None)


@pytest_asyncio.fixture
async def test_db():
    database._db = None
    db = await database.get_db()
    yield db
    await database.close_db()


# ------------------------------------------------------------------- status

def test_status_is_off_when_nothing_is_bound():
    assert network_monitoring() == "off"


def test_status_is_off_when_the_watcher_job_is_not_registered():
    bind_scheduler(_FakeScheduler(running=True, job_ids={"process_watcher", "aggregator_flush"}))
    assert network_monitoring() == "off"


def test_status_is_off_when_the_scheduler_is_not_running():
    bind_scheduler(_FakeScheduler(running=False, job_ids={NETWORK_WATCHER_JOB_ID}))
    assert network_monitoring() == "off"


def test_status_flips_to_on_when_the_watcher_job_is_registered_and_running():
    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID}))
    assert network_monitoring() == "on"


def test_status_survives_a_broken_scheduler():
    class Broken:
        running = True

        def get_job(self, _):
            raise RuntimeError("boom")

    bind_scheduler(Broken())
    assert network_monitoring() == "off"


def test_main_registers_the_job_under_the_id_the_status_reads():
    """The disabled registration in main.py and the status check must agree
    on the job id, or re-enabling the watcher would not flip the status."""
    source = (Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8")
    assert f'id="{NETWORK_WATCHER_JOB_ID}"' in source


@pytest.mark.asyncio
async def test_health_reports_network_monitoring_from_real_state(test_db):
    import main as main_module

    assert (await main_module.health())["network_monitoring"] == "off"
    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID}))
    assert (await main_module.health())["network_monitoring"] == "on"


# -------------------------------------------------------------- notes / JSON

def test_off_note_is_present_only_while_the_watcher_is_off():
    assert export_module.NETWORK_OFF_NOTE in export_module.current_report_notes()
    assert export_module.NETWORK_OFF_NOTE == (
        "Network connections are not monitored in this version. "
        "Unrecognised-destination alerts are therefore not produced."
    )

    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID}))
    on_notes = export_module.current_report_notes()
    assert export_module.NETWORK_OFF_NOTE not in on_notes
    assert on_notes == export_module.REPORT_NOTES + [export_module.MCP_OFF_NOTE]   # MCP still off

    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID, "mcp_watcher"}))
    assert export_module.current_report_notes() == export_module.REPORT_NOTES


def _client_for(summary):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    async def fake_build_summary(date, tz=None):
        return dict(summary)

    app = FastAPI()
    app.include_router(export_module.router)
    return TestClient(app), patch.object(export_module, "_build_summary", fake_build_summary)


def _pdf_text(summary) -> str:
    from reportlab.pdfgen import canvas

    drawn = []
    original = canvas.Canvas.drawString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    client, build_patch = _client_for(summary)
    with build_patch, patch.object(canvas.Canvas, "drawString", capture):
        assert client.get("/export/pdf").status_code == 200
    return " ".join(drawn)


@pytest.mark.asyncio
async def test_json_and_pdf_show_off_status_and_note_then_flip_to_on(test_db):
    summary_off = await export_module._build_summary("today")
    assert summary_off["network_monitoring"] == "off"
    assert export_module.NETWORK_OFF_NOTE in summary_off["report_notes"]

    client, build_patch = _client_for(summary_off)
    with build_patch:
        data = client.get("/export/json").json()
    assert data["network_monitoring"] == "off"
    assert export_module.NETWORK_OFF_NOTE in data["report_notes"]

    text = _pdf_text(summary_off)
    assert "Network monitoring: off" in text
    assert "Network connections are not monitored in this version." in text
    assert "Unrecognised-destination alerts are therefore not produced." in text

    # Simulate the watcher being re-enabled.
    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID}))
    summary_on = await export_module._build_summary("today")
    assert summary_on["network_monitoring"] == "on"
    assert export_module.NETWORK_OFF_NOTE not in summary_on["report_notes"]

    client, build_patch = _client_for(summary_on)
    with build_patch:
        data_on = client.get("/export/json").json()
    assert data_on["network_monitoring"] == "on"
    assert export_module.NETWORK_OFF_NOTE not in data_on["report_notes"]

    text_on = _pdf_text(summary_on)
    assert "Network monitoring: on" in text_on
    assert "Network connections are not monitored" not in text_on


# ------------------------------------------------------------ session report

@pytest.mark.asyncio
async def test_session_report_does_not_show_zero_connections_while_off(test_db):
    from reportlab.pdfgen import canvas

    import api.sessions as sessions_module

    name = f"claude_code_netoff_{uuid.uuid4().hex[:8]}"
    cur = await test_db.execute(
        "INSERT INTO agents (name, process_name, pid, approved) VALUES (?, ?, NULL, 1)", (name, name),
    )
    sid = f"sess_{uuid.uuid4().hex[:8]}"
    await test_db.execute(
        "INSERT INTO sessions (id, agent_id, started_at, ended_at) VALUES (?, ?, '2026-03-01 10:00:00', '2026-03-01 10:10:00')",
        (sid, cur.lastrowid),
    )
    await test_db.commit()

    drawn = []
    original = canvas.Canvas.drawString
    original_centred = canvas.Canvas.drawCentredString

    def capture(self, x, y, text):
        drawn.append(text)
        return original(self, x, y, text)

    def capture_centred(self, x, y, text):
        drawn.append(text)
        return original_centred(self, x, y, text)

    with patch.object(canvas.Canvas, "drawString", capture), patch.object(canvas.Canvas, "drawCentredString", capture_centred):
        await sessions_module.get_session_report_pdf(sid)

    joined = " | ".join(drawn)
    assert "Network Connections (not monitored in this version)" in joined
    assert "Network Connections (0)" not in joined
    assert "Network monitoring is off, so connections are not recorded." in joined
    assert "off" in drawn, "the summary box shows 'off', not 0"


# ------------------------------------------------------- no overclaim strings

def test_generated_report_text_does_not_claim_network_visibility():
    from core.digest import generate_summary

    quiet = generate_summary("claude_code", {})
    assert "network" not in quiet.lower()

    claims = [n for n in export_module.REPORT_NOTES if re.search(r"network|destination", n, re.I)]
    assert claims == [], "REPORT_NOTES itself must not mention network; only the off-note does"

    from api.mcp_routes import TOOLS  # noqa: F401  (name checked below)
    red_line_tool = next(t for t in TOOLS if t["name"] == "get_red_line_events")
    assert "network" not in red_line_tool["description"].lower()


def test_ui_strings_do_not_claim_network_monitoring():
    frontend = Path(__file__).resolve().parents[2] / "frontend" / "src" / "components"
    if not frontend.exists():
        pytest.skip("frontend sources not present")
    welcome = (frontend / "WelcomeScreen.jsx").read_text(encoding="utf-8")
    assert "Network connections they open" not in welcome
    for name in ("LiveFeed.jsx", "History.jsx"):
        text = (frontend / name).read_text(encoding="utf-8")
        assert "● Network connections" not in text, name
        assert "No network activity yet." not in text, name
    assert "Network calls" not in (frontend / "AgentDetail.jsx").read_text(encoding="utf-8")
