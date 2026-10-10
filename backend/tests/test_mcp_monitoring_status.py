"""The MCP watcher is deliberately off (see the comment above the disabled
mcp_watcher job in main.py). Same honesty pattern as network monitoring:
a status read from the scheduler, a report note shown only while off, and
no UI text claiming MCP call monitoring. See conftest.py for why
VLAW_DATA_DIR is set there rather than here."""

from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio

import api.export as export_module
import db.database as database
from core.monitoring_status import MCP_WATCHER_JOB_ID, NETWORK_WATCHER_JOB_ID, bind_scheduler, mcp_monitoring


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

def test_mcp_status_off_when_unbound_or_job_missing_or_scheduler_stopped():
    assert mcp_monitoring() == "off"
    bind_scheduler(_FakeScheduler(running=True, job_ids={"process_watcher"}))
    assert mcp_monitoring() == "off"
    bind_scheduler(_FakeScheduler(running=False, job_ids={MCP_WATCHER_JOB_ID}))
    assert mcp_monitoring() == "off"


def test_mcp_status_flips_to_on_when_the_job_is_registered_and_running():
    bind_scheduler(_FakeScheduler(running=True, job_ids={MCP_WATCHER_JOB_ID}))
    assert mcp_monitoring() == "on"


def test_mcp_and_network_statuses_are_independent():
    from core.monitoring_status import network_monitoring

    bind_scheduler(_FakeScheduler(running=True, job_ids={MCP_WATCHER_JOB_ID}))
    assert mcp_monitoring() == "on" and network_monitoring() == "off"
    bind_scheduler(_FakeScheduler(running=True, job_ids={NETWORK_WATCHER_JOB_ID}))
    assert mcp_monitoring() == "off" and network_monitoring() == "on"


def test_main_registers_the_job_under_the_id_the_status_reads():
    source = (Path(__file__).resolve().parent.parent / "main.py").read_text(encoding="utf-8")
    assert f'id="{MCP_WATCHER_JOB_ID}"' in source


@pytest.mark.asyncio
async def test_health_reports_mcp_monitoring_from_real_state(test_db):
    import main as main_module

    assert (await main_module.health())["mcp_monitoring"] == "off"
    bind_scheduler(_FakeScheduler(running=True, job_ids={MCP_WATCHER_JOB_ID}))
    assert (await main_module.health())["mcp_monitoring"] == "on"


# ------------------------------------------------------------ notes / exports

def test_mcp_off_note_only_while_off():
    assert export_module.MCP_OFF_NOTE in export_module.current_report_notes()
    assert export_module.MCP_OFF_NOTE.startswith("MCP server connections are not monitored in this version.")

    bind_scheduler(_FakeScheduler(running=True, job_ids={MCP_WATCHER_JOB_ID}))
    assert export_module.MCP_OFF_NOTE not in export_module.current_report_notes()


def _client_and_patch(summary):
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

    client, build_patch = _client_and_patch(summary)
    with build_patch, patch.object(canvas.Canvas, "drawString", capture):
        assert client.get("/export/pdf").status_code == 200
    return " ".join(drawn)


@pytest.mark.asyncio
async def test_json_and_pdf_show_mcp_status_and_note_then_flip(test_db):
    summary_off = await export_module._build_summary("today")
    assert summary_off["mcp_monitoring"] == "off"
    assert export_module.MCP_OFF_NOTE in summary_off["report_notes"]

    client, build_patch = _client_and_patch(summary_off)
    with build_patch:
        data = client.get("/export/json").json()
    assert data["mcp_monitoring"] == "off"
    assert export_module.MCP_OFF_NOTE in data["report_notes"]

    text = _pdf_text(summary_off)
    assert "MCP monitoring: off" in text
    assert "MCP server connections are not monitored in this version." in text

    bind_scheduler(_FakeScheduler(running=True, job_ids={MCP_WATCHER_JOB_ID}))
    summary_on = await export_module._build_summary("today")
    assert summary_on["mcp_monitoring"] == "on"
    assert export_module.MCP_OFF_NOTE not in summary_on["report_notes"]

    client, build_patch = _client_and_patch(summary_on)
    with build_patch:
        data_on = client.get("/export/json").json()
    assert data_on["mcp_monitoring"] == "on"
    assert export_module.MCP_OFF_NOTE not in data_on["report_notes"]
    text_on = _pdf_text(summary_on)
    assert "MCP monitoring: on" in text_on
    assert "MCP server connections are not monitored" not in text_on


# ---------------------------------------------------------------- UI strings

def test_ui_does_not_claim_mcp_call_monitoring():
    components = Path(__file__).resolve().parents[2] / "frontend" / "src" / "components"
    if not components.exists():
        pytest.skip("frontend sources not present")
    for name in ("LiveFeed.jsx", "History.jsx"):
        text = (components / name).read_text(encoding="utf-8")
        assert "MCP tool calls" not in text, name
        assert "MCP configuration changes" not in text, name
    agent_detail = (components / "AgentDetail.jsx").read_text(encoding="utf-8")
    assert "MCP connections" not in agent_detail
    assert "Files accessed" not in agent_detail
