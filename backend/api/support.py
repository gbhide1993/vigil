"""Support bundle: one zip a pilot customer can save and send by hand.

Nothing is uploaded; the tray asks for this zip over loopback and the user chooses
where to save it. The bundle is built from an allow-list of entries (see
BUNDLE_ENTRIES). It never includes the database, events, alerts, session contents,
commands, the policy file or any license file.
"""

import io
import json
import os
import platform
import sys
import zipfile
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from core import runtime_state
from core.monitoring_status import file_watcher_tier, mcp_monitoring, network_monitoring
from core.scope_store import get_scope_directories
from db.database import get_read_db

router = APIRouter()

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}

# Fixed names inside the zip; log files are added as logs/<name> (see _log_files).
BUNDLE_ENTRIES = ("README.txt", "health.json", "build-info.json", "monitoring-status.txt", "watched-folders.txt")
LOG_DIR_IN_ZIP = "logs/"

INCLUDED = [
    "Vigil's log file and its rotated copies (vlaw-backend.log*)",
    "The health check output (what /api/health returns)",
    "Version and build information",
    "Monitoring and coverage status text",
    "The list of watched folder paths",
]
EXCLUDED = [
    "The database, events, alerts and session contents",
    "Commands and file contents",
    "The policy file and any license file",
]

README = """Vigil support bundle
====================

Made on this computer when you chose "Save support logs". Nothing was uploaded.

Included: the Vigil log file and its rotated copies (logs/), the health check output
(health.json), version and build information (build-info.json), monitoring and coverage
status text (monitoring-status.txt) and the list of watched folder paths
(watched-folders.txt).

Not included: the database, events, alerts, session contents, commands, file contents,
the policy file and any license file.

The log file can still contain file paths, agent names and error messages from this
computer. Look through it before sending if that matters to you.
"""


def _require_loopback(request: Request) -> None:
    client = request.client.host if request.client else None
    if client not in _LOOPBACK and client != "testclient":
        raise HTTPException(status_code=403, detail="The support bundle can only be made from this computer.")


def _log_files() -> list[str]:
    log_path = runtime_state.state.get("log_path")
    if not log_path:
        return []
    folder, base = os.path.split(os.path.abspath(log_path))
    try:
        names = sorted(n for n in os.listdir(folder) if n == base or n.startswith(base + "."))
    except OSError:
        return []
    return [os.path.join(folder, n) for n in names if os.path.isfile(os.path.join(folder, n))]


async def _health_text() -> str:
    provider = runtime_state.state.get("health_fn")
    try:
        data = await provider() if provider else {"error": "health check not available"}
    except Exception as exc:  # the bundle must still be produced when the backend is unwell
        data = {"error": f"health check failed: {type(exc).__name__}"}
    return json.dumps(data, indent=2, default=str)


def _build_info() -> str:
    return json.dumps({
        "version": runtime_state.state.get("version"),
        "frozen_build": bool(getattr(sys, "frozen", False)),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2)


def _monitoring_text() -> str:
    from api.export import current_report_notes

    lines = [
        f"network_monitoring: {network_monitoring()}",
        f"mcp_monitoring: {mcp_monitoring()}",
        f"file_watcher_tier: {file_watcher_tier()}",
        "",
        "Coverage notes (as printed in reports):",
    ]
    lines += [f"- {note}" for note in current_report_notes()]
    return "\n".join(lines) + "\n"


async def _watched_text() -> str:
    from watchers.file_watcher import watched_paths

    db = await get_read_db()
    try:
        folders = await get_scope_directories(db)
    finally:
        await db.close()
    observer = runtime_state.state.get("observer")
    observed = watched_paths(observer) if observer is not None else []
    lines = ["Project folders added in Settings:"] + ([f"- {p}" for p in folders] or ["- none"])
    lines += ["", "Paths the live file watcher is observing:"] + ([f"- {p}" for p in observed] or ["- none"])
    return "\n".join(lines) + "\n"


@router.get("/support/contents")
async def support_contents(request: Request):
    """What the bundle does and does not contain, for the tray's confirmation dialog."""
    _require_loopback(request)
    return {"included": INCLUDED, "excluded": EXCLUDED}


@router.post("/support/bundle")
async def support_bundle(request: Request):
    _require_loopback(request)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", README)
        archive.writestr("health.json", await _health_text())
        archive.writestr("build-info.json", _build_info())
        archive.writestr("monitoring-status.txt", _monitoring_text())
        archive.writestr("watched-folders.txt", await _watched_text())
        for path in _log_files():
            archive.write(path, LOG_DIR_IN_ZIP + os.path.basename(path))
    name = f"vigil-support-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    return Response(
        content=buffer.getvalue(), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
