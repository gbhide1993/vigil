import io
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from db.database import get_db

router = APIRouter()


def _format_local(ts: str) -> str:
    """Parse a stored UTC timestamp (naive 'YYYY-MM-DD HH:MM:SS' or an
    isoformat string with an explicit offset) and format it in the
    system's local timezone, labelled with the local zone name/offset."""
    dt = datetime.fromisoformat(ts.replace(" ", "T"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def _date_bounds(date: str) -> tuple[str, str]:
    if date == "today":
        day = datetime.now(timezone.utc).date()
    else:
        try:
            day = datetime.fromisoformat(date).date()
        except ValueError:
            raise HTTPException(400, "date must be 'today' or YYYY-MM-DD")
    start = f"{day.isoformat()} 00:00:00"
    end = f"{day.isoformat()} 23:59:59"
    return start, end


async def _build_summary(date: str) -> dict:
    db = await get_db()
    start, end = _date_bounds(date)

    cur = await db.execute(
        "SELECT * FROM sessions WHERE started_at BETWEEN ? AND ?", (start, end)
    )
    sessions = [dict(r) for r in await cur.fetchall()]

    cur = await db.execute(
        """
        SELECT al.*, a.name as agent_name FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        WHERE al.created_at BETWEEN ? AND ?
        """,
        (start, end),
    )
    alerts = [dict(r) for r in await cur.fetchall()]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE created_at BETWEEN ? AND ?", (start, end)
    )
    event_count = (await cur.fetchone())["c"]

    return {
        "date": date,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": event_count,
        "sessions": sessions,
        "alerts": alerts,
    }


@router.get("/export/json")
async def export_json(date: str = Query(default="today")):
    return await _build_summary(date)


@router.get("/export/pdf")
async def export_pdf(date: str = Query(default="today")):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas

    summary = await _build_summary(date)

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    y = height - inch
    c.setFont("Helvetica-Bold", 16)
    c.drawString(inch, y, "V-LAW Audit Report")
    y -= 0.3 * inch

    c.setFont("Helvetica", 10)
    c.drawString(inch, y, f"Date: {summary['date']}  Generated: {_format_local(summary['generated_at'])}")
    y -= 0.3 * inch
    c.drawString(inch, y, f"Events: {summary['event_count']}  Sessions: {len(summary['sessions'])}  Alerts: {len(summary['alerts'])}")
    y -= 0.4 * inch

    from core.evidence_chain import verify_chain
    # verify_chain() opens its own dedicated connection internally.
    chain_result = await verify_chain()
    chain_status = "VERIFIED INTACT" if chain_result["valid"] else f"INTEGRITY FAILURE: {chain_result['reason']}"
    c.setFont("Helvetica-Bold", 10)
    c.drawString(inch, y, f"Evidence chain: {chain_status} ({chain_result['checked_count']} events checked)")
    y -= 0.3 * inch

    c.setFont("Helvetica-Bold", 12)
    c.drawString(inch, y, "Sessions")
    y -= 0.25 * inch
    c.setFont("Helvetica", 9)
    for session in summary["sessions"]:
        if y < inch:
            c.showPage()
            y = height - inch
            c.setFont("Helvetica", 9)
        operator = f"{session.get('operator_username') or 'unknown'}@{session.get('operator_hostname') or 'unknown'}"
        line = f"{session['id'][:8]}  operator={operator}  started={_format_local(session['started_at'])}"
        c.drawString(inch, y, line[:110])
        y -= 0.2 * inch
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    c.drawString(inch, y, "Alerts")
    y -= 0.25 * inch
    c.setFont("Helvetica", 9)

    for alert in summary["alerts"]:
        if y < inch:
            c.showPage()
            y = height - inch
            c.setFont("Helvetica", 9)
        line = f"[{alert['severity'].upper()}] {alert['title']} (status={alert['status']})"
        c.drawString(inch, y, line[:110])
        y -= 0.2 * inch

    c.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vlaw-report-{summary['date']}.pdf"},
    )
