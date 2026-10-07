import io
from datetime import datetime, timedelta, timezone

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


def _resolve_local_day(date: str, tz=None):
    """The calendar date `date` ("today" or YYYY-MM-DD) refers to in this
    machine's LOCAL timezone. "today" must mean today where this machine
    physically is, not today in UTC -- those already disagree for part of
    every day in any timezone ahead of UTC (e.g. just after local
    midnight in IST, UTC is still "yesterday").

    tz lets a test pin a specific zoneinfo-aware timezone instead of this
    machine's real one. Windows has no equivalent of POSIX's
    time.tzset() to change a process's effective local timezone for a
    test, so this is the hook tests use instead; production code never
    passes it, and the default behaves exactly as before."""
    if date == "today":
        now = datetime.now(tz) if tz is not None else datetime.now().astimezone()
        return now.date()
    try:
        return datetime.fromisoformat(date).date()
    except ValueError:
        raise HTTPException(400, "date must be 'today' or YYYY-MM-DD")


def _local_day_bounds_utc(day, tz=None) -> tuple[datetime, datetime]:
    """Local midnight at the start of `day` to local midnight at the start
    of the next calendar day, each independently converted to UTC.

    The next boundary is deliberately computed from the next calendar
    DATE (day + timedelta(days=1), plain date arithmetic), not by adding
    a 24-hour timedelta to the start datetime -- a fixed 24 hours lands
    on the wrong wall-clock time on a DST-transition day, which has 23 or
    25 real hours, not 24.

    With tz=None (production), each midnight is built as a naive datetime
    and converted to UTC separately: astimezone() on a naive datetime
    treats it as system local time and resolves the correct UTC offset
    for that specific calendar date, so a DST change inside the period
    doesn't throw either boundary off. With an explicit zoneinfo-aware tz
    (tests only), each midnight is built directly in that zone instead,
    which is independently DST-correct per date the same way."""
    next_day = day + timedelta(days=1)
    if tz is not None:
        start_local = datetime.combine(day, datetime.min.time(), tzinfo=tz)
        end_local = datetime.combine(next_day, datetime.min.time(), tzinfo=tz)
    else:
        start_local = datetime.combine(day, datetime.min.time())
        end_local = datetime.combine(next_day, datetime.min.time())
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


async def _build_summary(date: str, tz=None) -> dict:
    db = await get_db()
    day = _resolve_local_day(date, tz)
    start_utc, end_utc = _local_day_bounds_utc(day, tz)
    # DB timestamps are naive UTC strings -- same format the rest of the
    # codebase already queries against (see main.py's /api/stats).
    start_sql = start_utc.strftime("%Y-%m-%d %H:%M:%S")
    end_sql = end_utc.strftime("%Y-%m-%d %H:%M:%S")

    cur = await db.execute(
        "SELECT * FROM sessions WHERE started_at >= ? AND started_at < ?", (start_sql, end_sql)
    )
    sessions = [dict(r) for r in await cur.fetchall()]

    cur = await db.execute(
        """
        SELECT al.*, a.name as agent_name FROM alerts al
        LEFT JOIN agents a ON a.id = al.agent_id
        WHERE al.created_at >= ? AND al.created_at < ?
        """,
        (start_sql, end_sql),
    )
    alerts = [dict(r) for r in await cur.fetchall()]

    cur = await db.execute(
        "SELECT COUNT(*) c FROM events WHERE created_at >= ? AND created_at < ?", (start_sql, end_sql)
    )
    event_count = (await cur.fetchone())["c"]

    return {
        # Always the resolved real calendar date, never the literal
        # string "today" -- this is also what drives the download
        # filenames below, so "today" never leaks into a saved file name.
        "date": day.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_start": start_utc.isoformat(),
        "period_end": end_utc.isoformat(),
        "timezone": start_utc.astimezone(tz).strftime("%Z") if tz is not None else start_utc.astimezone().strftime("%Z"),
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

    # period_start/period_end are UTC ISO; converting each back to local
    # time for display here (rather than storing a pre-formatted string in
    # the summary) keeps _build_summary's return value machine-readable
    # for the JSON export and lets the PDF format it however it needs to.
    period_start_local = datetime.fromisoformat(summary["period_start"]).astimezone()
    period_end_local = datetime.fromisoformat(summary["period_end"]).astimezone()
    period_label = (
        f"Period: {period_start_local.strftime('%d %b %Y %H:%M')} to "
        f"{period_end_local.strftime('%d %b %Y %H:%M')} {period_start_local.strftime('%Z')}"
    )

    y = height - inch
    c.setFont("Helvetica-Bold", 16)
    c.drawString(inch, y, "Vigil Audit Report")
    y -= 0.3 * inch

    c.setFont("Helvetica", 10)
    c.drawString(inch, y, f"{period_label}  Generated: {_format_local(summary['generated_at'])}")
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
        headers={"Content-Disposition": f"attachment; filename=vigil-report-{summary['date']}.pdf"},
    )
