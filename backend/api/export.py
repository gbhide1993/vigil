import io
from datetime import datetime, timezone

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from db.database import get_db

router = APIRouter()


def _date_bounds(date: str) -> tuple[str, str]:
    if date == "today":
        day = datetime.now(timezone.utc).date()
    else:
        day = datetime.fromisoformat(date).date()
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
    c.drawString(inch, y, f"Date: {summary['date']}  Generated: {summary['generated_at']}")
    y -= 0.3 * inch
    c.drawString(inch, y, f"Events: {summary['event_count']}  Sessions: {len(summary['sessions'])}  Alerts: {len(summary['alerts'])}")
    y -= 0.4 * inch

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
