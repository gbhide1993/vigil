import io
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from collections import Counter

from core import report_coverage
from core.alerter import Alerter
from core.digest import display_summary
from core.file_changes import scope_label, session_changes
from core.monitoring_status import network_monitoring
from core.scope_store import get_scope_directories
from core.verification import build_verification_report, touches_credential_path
from db.database import get_read_db

router = APIRouter()
_alerter = Alerter()

# Most file-change rows listed in one session report (the rest are counted).
MAX_FILE_CHANGE_ROWS = 200

ANOMALY_RULE_TYPES = ("volumetric_threshold", "time_anomaly", "ratio_anomaly", "unknown_destination", "rolling_anomaly")


@router.get("/sessions")
async def get_sessions(status: str | None = Query(default=None)):
    """Global session listing across all agents. status=open restricts to
    sessions that haven't closed yet (ended_at IS NULL) — used by the tray
    for an active-agent count. Also one of the app shell's always-on 3s
    polls (App.jsx, until the first session shows up).

    net_connect_count used to be a correlated scalar subquery -- one
    SELECT COUNT(*) FROM events ... re-run per session row. events has
    no index on session_id, so each of those per-row subqueries fell
    back to scanning every net_connect-type event checking session_id by
    hand. Measured directly: p95 11.5s at 900 sessions / 15k events (the
    performance gate in tests/test_perf_gate.py). Fixed by pre-aggregating
    net_connect counts for every session in one GROUP BY pass (one scan
    of events total, not one per session row) joined in once, plus a new
    idx_events_session index for this and any other session_id-filtered
    query."""
    db = await get_read_db()
    try:
        where = "WHERE s.ended_at IS NULL" if status == "open" else ""
        cur = await db.execute(
            f"""
            SELECT s.*, a.name as agent_name,
                COALESCE(nc.net_connect_count, 0) as net_connect_count
            FROM sessions s
            LEFT JOIN agents a ON a.id = s.agent_id
            LEFT JOIN (
                SELECT session_id, COUNT(*) as net_connect_count
                FROM events
                WHERE event_type = 'net_connect'
                GROUP BY session_id
            ) nc ON nc.session_id = s.id
            {where}
            ORDER BY s.started_at DESC
            """
        )
        rows = await cur.fetchall()
        sessions = [dict(r) for r in rows]
        for s in sessions:
            s["summary"] = display_summary(s.get("summary"))
        return {"sessions": sessions}
    finally:
        await db.close()


@router.get("/sessions/{session_id}/verify")
async def verify_session(session_id: str):
    """Compares this session's agent-self-reported file activity (Claude
    Code's own .jsonl transcript) against what V-LAW independently
    observed at the OS level. See core/verification.py for the comparison
    logic. A non-empty discrepancies list fires a verification_mismatch
    alert as a side effect — that's the significant, actionable case."""
    db = await get_read_db()
    try:
        cur = await db.execute("SELECT id, agent_id FROM sessions WHERE id = ?", (session_id,))
        session = await cur.fetchone()
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")

        cur = await db.execute("SELECT name FROM agents WHERE id = ?", (session["agent_id"],))
        agent = await cur.fetchone()
        agent_name = agent["name"] if agent else "unknown agent"

        report = await build_verification_report(session_id, agent_name, db)
    finally:
        await db.close()

    # fire_alert opens its own dedicated get_db() connection internally --
    # intentionally outside the read-only connection's try/finally above,
    # since this is the one write this handler can trigger as a side
    # effect and must never run on a query_only connection.
    discrepancies = report.get("discrepancies")
    if discrepancies:
        await _fire_verification_mismatch_alert(session["agent_id"], agent_name, session_id, discrepancies)

    return report


async def _fire_verification_mismatch_alert(agent_id: int, agent_name: str, session_id: str, discrepancies: list[dict]) -> None:
    has_credential_mismatch = any(
        d["seen_by"] == "os_only" and touches_credential_path(d["path"])
        for d in discrepancies
    )
    severity = "high" if has_credential_mismatch else "medium"
    count = len(discrepancies)

    await _alerter.fire_alert(
        agent_id,
        severity,
        title=f"{agent_name}'s own session log does not match observed OS activity — {count} discrepancies found",
        description=f"Session {session_id}: {count} file path(s) differ between {agent_name}'s self-reported "
                     "session transcript and what V-LAW independently observed at the OS level.",
        reason="verification_mismatch",
        extra_detail={"session_id": session_id, "discrepancy_count": count, "discrepancies": discrepancies[:50]},
        rule_type="verification_mismatch",
        target=session_id,
        session_id=session_id,
    )


@router.get("/sessions/{session_id}/top-finding")
async def get_session_top_finding(session_id: str):
    """The single most interesting alert for a closed session, in priority
    order: Red Line alert, then Layer 2a/2b anomaly, then None (caller
    falls back to a plain event-count summary). Alerts aren't linked to a
    session directly — event-driven alerts carry it via events.session_id,
    session-close alerts (Layer 2a/2b) carry it in audit_log.detail — so
    both sources are checked."""
    db = await get_read_db()
    try:
        async def _find(rule_type_clause: str, params: tuple) -> dict | None:
            cur = await db.execute(
                f"""
                SELECT al.* FROM alerts al
                WHERE {rule_type_clause}
                  AND (
                    al.event_id IN (SELECT id FROM events WHERE session_id = ?)
                    OR al.id IN (
                        SELECT CAST(json_extract(detail, '$.alert_id') AS INTEGER)
                        FROM audit_log
                        WHERE action = 'alert_created' AND json_extract(detail, '$.session_id') = ?
                    )
                  )
                ORDER BY al.created_at ASC
                LIMIT 1
                """,
                (*params, session_id, session_id),
            )
            row = await cur.fetchone()
            return dict(row) if row else None

        red_line = await _find("al.rule_type = ?", ("red_line",))
        if red_line:
            return {"kind": "red_line", "alert": red_line}

        placeholders = ", ".join("?" for _ in ANOMALY_RULE_TYPES)
        anomaly = await _find(f"al.rule_type IN ({placeholders})", ANOMALY_RULE_TYPES)
        if anomaly:
            return {"kind": "anomaly", "alert": anomaly}

        return {"kind": None, "alert": None}
    finally:
        await db.close()


async def _get_policy_list(db, key: str) -> list[str]:
    cur = await db.execute("SELECT policy_value FROM policy WHERE policy_key = ?", (key,))
    row = await cur.fetchone()
    return json.loads(row["policy_value"]) if row else []


async def _get_unique_network_destinations(db, session_id: str) -> list[str]:
    cur = await db.execute(
        "SELECT DISTINCT path FROM events WHERE session_id = ? AND event_type = 'net_connect' AND path IS NOT NULL",
        (session_id,),
    )
    rows = await cur.fetchall()
    return sorted(r["path"] for r in rows)


def _format_local(ts: str | None) -> str | None:
    """DB timestamps are stored as naive UTC strings. Parse as UTC, convert
    to the system's local timezone, and format for display."""
    if not ts:
        return ts
    dt = datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


async def _build_session_report(session_id: str) -> dict:
    """Assembles every data point the PDF/JSON session report needs, in one
    place, so the /report and /report/preview endpoints stay in sync."""
    db = await get_read_db()
    try:
        return await _build_session_report_data(db, session_id)
    finally:
        await db.close()


async def _build_session_report_data(db, session_id: str) -> dict:
    cur = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
    session = await cur.fetchone()
    if session is None:
        raise HTTPException(status_code=404, detail="session not found")

    cur = await db.execute("SELECT name FROM agents WHERE id = ?", (session["agent_id"],))
    agent = await cur.fetchone()
    agent_name = agent["name"] if agent else "unidentified_agent"

    started_at = session["started_at"]
    ended_at = session["ended_at"]
    duration_minutes = None
    if started_at:
        start_dt = datetime.fromisoformat(started_at.replace(" ", "T"))
        end_dt = datetime.fromisoformat(ended_at.replace(" ", "T")) if ended_at else datetime.utcnow()
        duration_minutes = round((end_dt - start_dt).total_seconds() / 60, 1)

    # Every recorded file change of the session (creates, writes, moves AND deletes),
    # with its time, change type and how sure the agent attribution is.
    scope_dirs = await get_scope_directories(db)
    changes, _rows_total = await session_changes(db, session_id, agent_name, limit=10000)
    for change in changes:
        change["scope"] = scope_label(change["path"], scope_dirs)
        change["is_credential"] = touches_credential_path(change["path"])
    by_change = dict(Counter(c["change"] for c in changes))
    shown_changes = changes[:MAX_FILE_CHANGE_ROWS]
    net_destinations = await _get_unique_network_destinations(db, session_id)
    approved_destinations = set(await _get_policy_list(db, "approved_network_destinations"))

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE session_id = ? AND event_type = 'proc_spawn'",
        (session_id,),
    )
    process_spawns = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT al.* FROM alerts al
        LEFT JOIN events e ON e.id = al.event_id
        WHERE al.severity IN ('high', 'critical')
          AND (al.session_id = ? OR e.session_id = ?)
        ORDER BY al.created_at ASC
        """,
        (session_id, session_id),
    )
    alerts = [dict(r) for r in await cur.fetchall()]
    for alert in alerts:
        alert["created_at"] = _format_local(alert["created_at"])

    # Unique paths (a file changed ten times is one entry here, ten in file_changes).
    unique: dict[str, dict] = {}
    for change in changes:
        unique.setdefault(change["path"], {
            "path": change["path"],
            # Under a watched folder? None when no folder is watched: then no label is shown.
            "scope": change["scope"],
            "outside_workdir": change["scope"] == "outside_scope",     # kept for older clients
            "is_credential": change["is_credential"],
        })
    files_touched = sorted(unique.values(), key=lambda f: f["path"])
    network_connections = [
        {"destination": d, "approved": d in approved_destinations}
        for d in net_destinations
    ]

    now_local = datetime.now(timezone.utc).astimezone()

    return {
        "session_id": session_id,
        "agent_name": agent_name,
        "start_time": _format_local(started_at),
        "end_time": _format_local(ended_at),
        "duration_minutes": duration_minutes,
        "generated_at": now_local.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "files_touched": files_touched,
        "files_touched_count": len(files_touched),
        "file_changes": shown_changes,
        "file_changes_total": len(changes),
        "file_changes_not_shown": len(changes) - len(shown_changes),
        "file_changes_by_type": by_change,
        "watched_folders": scope_dirs,
        "network_connections": network_connections,
        "network_connections_count": len(network_connections),
        # Real watcher state (core/monitoring_status.py): while "off", a count of 0
        # means "not measured", never "no connections".
        "network_monitoring": network_monitoring(),
        "process_spawns": process_spawns,
        "red_lines": alerts,
        "red_lines_count": len(alerts),
    }


@router.get("/sessions/{session_id}/report/preview")
async def get_session_report_preview(session_id: str):
    """JSON preview of the PDF report, for the frontend to render before
    the user downloads the actual file."""
    report = await _build_session_report(session_id)
    events = (
        [{"kind": "file", **c} for c in report["file_changes"]]
        + [{"kind": "network", **n} for n in report["network_connections"]]
    )
    return {
        "session_id": report["session_id"],
        "agent_name": report["agent_name"],
        "start_time": report["start_time"],
        "duration_minutes": report["duration_minutes"],
        "files_touched": report["files_touched_count"],
        "file_changes_total": report["file_changes_total"],
        "file_changes_not_shown": report["file_changes_not_shown"],
        "file_changes_by_type": report["file_changes_by_type"],
        "watched_folders": report["watched_folders"],
        "network_connections": report["network_connections_count"],
        "network_monitoring": report["network_monitoring"],
        "process_spawns": report["process_spawns"],
        "red_lines": report["red_lines_count"],
        "events": events,
        "alerts": report["red_lines"],
        "what_this_report_covers": report_coverage.as_dict(),
    }


@router.get("/sessions/{session_id}/report")
async def get_session_report_pdf(session_id: str):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas

    report = await _build_session_report(session_id)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 0.75 * inch

    def new_page():
        c.showPage()
        c.setFont("Helvetica", 9)
        return height - margin

    y = height - margin

    # HEADER
    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin, y, "Vigil — AI Session Monitor")
    y -= 0.28 * inch

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.black)
    c.drawString(margin, y, f"Session: {session_id[:8]}    Agent: {report['agent_name']}")
    y -= 0.2 * inch
    duration_str = f"{report['duration_minutes']} min" if report["duration_minutes"] is not None else "n/a"
    c.drawString(margin, y, f"Started: {report['start_time']}    Duration: {duration_str}")
    y -= 0.2 * inch
    c.drawString(margin, y, f"Generated: {report['generated_at']}")
    y -= 0.35 * inch

    c.setStrokeColor(colors.HexColor("#cccccc"))
    c.line(margin, y, width - margin, y)
    y -= 0.25 * inch

    # WHAT THIS REPORT COVERS: the same block as the daily PDF and the JSON export (core/report_coverage.py).
    c.setFont("Helvetica-Bold", 10)
    c.drawString(margin, y, report_coverage.TITLE)
    y -= 0.19 * inch
    c.setFont("Helvetica", 8.5)
    for line in report_coverage.LINES:
        for part in _wrap_text(line, 105):
            if y < margin:
                y = new_page()
                c.setFont("Helvetica", 8.5)
            c.drawString(margin, y, part)
            y -= 0.15 * inch
    y -= 0.2 * inch

    # While network monitoring is off a count of 0 means "not measured".
    net_off = report.get("network_monitoring") == "off" and report["network_connections_count"] == 0

    # SUMMARY ROW
    box_labels = [
        ("Files Changed", report["files_touched_count"]),
        ("Network Connections", "off" if net_off else report["network_connections_count"]),
        ("Process Spawns", report["process_spawns"]),
        ("Red Lines", report["red_lines_count"]),
    ]
    box_w = (width - 2 * margin - 3 * 0.15 * inch) / 4
    box_h = 0.7 * inch
    x = margin
    for label, value in box_labels:
        is_red_lines = label == "Red Lines"
        c.setFillColor(colors.HexColor("#fdeaea") if is_red_lines and value else colors.HexColor("#f2f2f2"))
        c.roundRect(x, y - box_h, box_w, box_h, 4, stroke=0, fill=1)
        c.setFillColor(colors.HexColor("#b00020") if is_red_lines and value else colors.black)
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(x + box_w / 2, y - box_h + 0.4 * inch, str(value))
        c.setFillColor(colors.black)
        c.setFont("Helvetica", 8)
        c.drawCentredString(x + box_w / 2, y - box_h + 0.18 * inch, label)
        x += box_w + 0.15 * inch
    y -= box_h + 0.35 * inch

    # FILE CHANGES
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, f"File changes ({report['file_changes_total']})")
    y -= 0.22 * inch
    c.setFont("Helvetica", 9)
    if report["file_changes_by_type"]:
        by_type = ", ".join(f"{name} {count}" for name, count in sorted(report["file_changes_by_type"].items()))
        c.drawString(margin, y, f"By change: {by_type}")
        y -= 0.2 * inch
    if not report["watched_folders"]:
        c.drawString(margin, y, "No project folder is watched, so no scope label is shown.")
        y -= 0.2 * inch
    if not report["file_changes"]:
        c.drawString(margin, y, "(none recorded)")
        y -= 0.2 * inch
    for f in report["file_changes"]:
        if y < margin + 0.4 * inch:
            y = new_page()
        if f["is_credential"]:
            marker = "[CREDENTIAL PATH] "
            c.setFillColor(colors.HexColor("#b00020"))
        elif f["scope"] == "outside_scope":
            marker = "[OUTSIDE SCOPE] "
            c.setFillColor(colors.HexColor("#b25900"))
        elif f["scope"] == "in_scope":
            marker = "[OK] "
            c.setFillColor(colors.HexColor("#1a7a3c"))
        else:
            marker = ""
        c.setFont("Helvetica", 8)
        c.drawString(margin, y, f"{marker}{f['time']}  {f['change']}  {f['path']}"[:150])
        y -= 0.15 * inch
        c.setFillColor(colors.black)
        confidence = f" ({f['attribution_confidence']})" if f["attribution_confidence"] and f["attribution"] != "exact" else ""
        c.drawString(margin + 0.25 * inch, y, f"{f['attribution_label']}{confidence}"[:140])
        y -= 0.17 * inch
    c.setFont("Helvetica", 9)
    if report["file_changes_not_shown"]:
        c.drawString(margin, y, f"{report['file_changes_not_shown']} more not shown (the counts above include them).")
        y -= 0.2 * inch
    y -= 0.2 * inch

    # NETWORK CONNECTIONS
    if y < margin:
        y = new_page()
    c.setFont("Helvetica-Bold", 12)
    if net_off:
        c.drawString(margin, y, "Network Connections (not monitored in this version)")
    else:
        c.drawString(margin, y, f"Network Connections ({report['network_connections_count']})")
    y -= 0.22 * inch
    c.setFont("Helvetica", 9)
    if net_off and not report["network_connections"]:
        c.drawString(margin, y, "Network monitoring is off, so connections are not recorded.")
        y -= 0.2 * inch
    elif not report["network_connections"]:
        c.drawString(margin, y, "(none)")
        y -= 0.2 * inch
    for n in report["network_connections"]:
        if y < margin:
            y = new_page()
        if n["approved"]:
            marker = "[APPROVED] "
            c.setFillColor(colors.HexColor("#1a7a3c"))
        else:
            marker = "[NOT IN POLICY] "
            c.setFillColor(colors.HexColor("#b25900"))
        c.drawString(margin, y, (marker + n["destination"])[:120])
        c.setFillColor(colors.black)
        y -= 0.18 * inch
    y -= 0.2 * inch

    # RED LINES (only if any fired)
    if report["red_lines"]:
        if y < margin:
            y = new_page()
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, f"Red Lines ({report['red_lines_count']})")
        y -= 0.24 * inch

        for alert in report["red_lines"]:
            if y < margin + 0.6 * inch:
                y = new_page()
            is_critical = alert["severity"] == "critical"
            c.setFont("Helvetica-Bold", 10)
            c.setFillColor(colors.HexColor("#b00020") if is_critical else colors.black)
            c.drawString(margin, y, f"[{alert['severity'].upper()}] {alert['title']}"[:110])
            y -= 0.18 * inch
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.HexColor("#666666"))
            c.drawString(margin, y, alert["created_at"] or "")
            y -= 0.16 * inch
            c.setFillColor(colors.black)
            c.setFont("Helvetica", 9)
            for line in _wrap_text(alert["description"], 100):
                if y < margin:
                    y = new_page()
                c.drawString(margin, y, line)
                y -= 0.16 * inch
            y -= 0.12 * inch

    # LEGEND
    legend_lines = [
        "[APPROVED] — destination is in your approved policy list",
        "[NOT IN POLICY] — destination not reviewed; verify if expected",
        "[OK] - change inside a watched folder",
        "[OUTSIDE SCOPE] - change outside the watched folders (shown only when a folder is watched)",
        "[CREDENTIAL PATH] - change to a sensitive credential file",
        "[CRITICAL] — immediate action required",
        "[HIGH] — review recommended",
        "[MEDIUM] — informational",
    ]
    legend_height = 0.22 * inch + len(legend_lines) * 0.13 * inch
    if y - legend_height < margin:
        y = new_page()

    c.setStrokeColor(colors.HexColor("#cccccc"))
    c.line(margin, y, width - margin, y)
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 7)
    c.setFillColor(colors.HexColor("#888888"))
    c.drawString(margin, y, "Legend:")
    y -= 0.15 * inch

    c.setFont("Helvetica", 7)
    for line in legend_lines:
        if y < margin:
            y = new_page()
        c.drawString(margin, y, line)
        y -= 0.13 * inch
    c.setFillColor(colors.black)

    # FOOTER
    c.setFont("Helvetica-Oblique", 8)
    c.setFillColor(colors.HexColor("#888888"))
    c.drawString(margin, margin - 0.35 * inch, "Generated by Vigil — Independent OS-level observer")
    c.drawString(margin, margin - 0.5 * inch, "Evidence is captured independently of agent self-reporting")

    c.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vigil-session-{session_id[:8]}.pdf"},
    )


def _wrap_text(text: str, width: int) -> list[str]:
    """Naive word-wrap for PDF body text — good enough for alert
    descriptions, which are short, plain-English sentences."""
    if not text:
        return []
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines
