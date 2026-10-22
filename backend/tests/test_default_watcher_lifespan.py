"""With VLAW_FILE_WATCHER unset, the real startup (main.lifespan, in this process) uses the native watcher, the
scheduled burst check reaches the handler that is current when it runs, and shutdown stops the native watcher."""

import pytest
from fastapi.testclient import TestClient

import main as main_module
from watchers import file_watcher


@pytest.fixture
def started(monkeypatch):
    # main.lifespan changes process-wide state (the ETW scope roots, the tier and reason, the runtime handles).
    from core import monitoring_status, runtime_state
    from core.scope_filter import etw_scope

    roots = etw_scope._roots          # None until loaded, which means "allow everything"
    status = (monitoring_status._file_tier, monitoring_status._etw_reason, monitoring_status._etw_requested)
    handles = dict(runtime_state.state)
    monkeypatch.delenv(file_watcher.FILE_WATCHER_ENV, raising=False)
    monkeypatch.delenv("VLAW_HOST_ROOT", raising=False)
    calls = {"stop": 0, "burst": 0}
    real_start = file_watcher.start_file_watcher

    def start_and_spy(*args, **kwargs):
        observer, handler = real_start(*args, **kwargs)
        real_stop = observer.stop

        def stop(*a, **k):
            calls["stop"] += 1
            return real_stop(*a, **k)

        async def burst():
            calls["burst"] += 1

        observer.stop = stop
        handler.check_burst = burst
        return observer, handler

    monkeypatch.setattr(main_module, "start_file_watcher", start_and_spy)
    yield calls
    etw_scope._roots = roots
    monitoring_status._file_tier, monitoring_status._etw_reason, monitoring_status._etw_requested = status
    runtime_state.state.clear()
    runtime_state.state.update(handles)


def test_default_start_is_native_the_burst_wrapper_runs_and_shutdown_stops_the_watcher(started):
    import asyncio

    with TestClient(main_module.app, base_url="http://localhost") as client:
        health = client.get("/health").json()
        assert health["file_watcher_tier"] == "native" and health["etw_available"] is False
        assert health["etw_requested"] is False and "off by default" in health["etw_unavailable_reason"]

        job = main_module._state["scheduler"].get_job("file_burst_check")
        assert job is not None, "the burst check is scheduled"
        asyncio.run(job.func())
        assert started["burst"] == 1, "the wrapper reached the current handler"
        assert started["stop"] == 0

    assert started["stop"] == 1, "shutdown stopped the native watcher"
