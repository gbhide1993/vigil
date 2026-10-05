"""Tests for main.py's _localhost_origin_guard middleware (Task 2 of the
P1 pilot sprint): a Host-header check that blocks DNS rebinding, plus an
Origin allowlist check on state-changing methods that blocks a hostile
web page from firing a body-less, non-preflighted POST against the
backend. See conftest.py for why VLAW_DATA_DIR is set there rather than
here -- this module must only ever touch that isolated temp DB, never
the real dev DB in backend/data/.

Targets /api/agents/999999999/approve for the POST cases: a real,
unconditionally-registered route (not gated by sys.frozen) that 404s on
a nonexistent agent id before any write, so these tests exercise real
routing/middleware behavior without mutating anything -- same approach
already used in tests/test_bugfixes.py and tests/test_evidence_chain.py
for endpoints that take an id."""

import pytest
from fastapi.testclient import TestClient

import main as main_module

client = TestClient(main_module.app, base_url="http://localhost")


def test_bad_origin_post_is_forbidden():
    resp = client.post(
        "/api/agents/999999999/approve",
        headers={"Origin": "http://evil.example"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "forbidden origin"


def test_no_origin_post_is_not_forbidden():
    resp = client.post("/api/agents/999999999/approve")
    # No Origin header at all (the real tray/VS Code/MCP clients never
    # send one) must reach the real handler, not be blocked by the
    # origin check -- 404 here means routing succeeded and the handler's
    # own not-found check ran, which is the expected outcome for a
    # nonexistent agent id.
    assert resp.status_code == 404


def test_bad_host_header_is_forbidden():
    resp = client.get("/api/health", headers={"Host": "evil.example"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "forbidden host"


def test_normal_localhost_get_succeeds():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.parametrize(
    "origin",
    ["http://localhost:7422", "http://127.0.0.1:7422", "http://localhost:5173"],
)
def test_allowlisted_origin_post_is_not_forbidden(origin):
    resp = client.post(
        "/api/agents/999999999/approve",
        headers={"Origin": origin},
    )
    assert resp.status_code == 404


@pytest.mark.parametrize("hostname", ["127.0.0.1", "[::1]"])
def test_allowlisted_host_header_variants_succeed(hostname):
    resp = client.get("/api/health", headers={"Host": f"{hostname}:7422"})
    assert resp.status_code == 200
