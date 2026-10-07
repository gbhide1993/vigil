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


def _wrap_line(text: str, font_name: str, font_size: float, max_width: float) -> list[str]:
    """Splits `text` on spaces into as many lines as needed so each one
    measures within max_width at (font_name, font_size), using reportlab's
    own stringWidth rather than guessing from a character count. A fixed
    character-count truncation (what this used to do, line[:110]) either
    cuts off real content or, for a wide font/size, still overflows the
    page width anyway -- stringWidth measures the actual rendered width.

    A single space-free token (a long operator=user@hostname string, a
    path, a URL) can itself be wider than max_width with no space to
    break on -- word-wrapping alone would leave it on one overflowing
    line. Any such token is pre-split character by character into
    max_width-sized chunks before the normal word-wrap pass runs, so
    every token the word-wrap loop sees already fits on its own."""
    from reportlab.pdfbase.pdfmetrics import stringWidth

    def split_oversized_token(token: str) -> list[str]:
        if stringWidth(token, font_name, font_size) <= max_width:
            return [token]
        chunks: list[str] = []
        current_chunk = ""
        for ch in token:
            candidate = current_chunk + ch
            if current_chunk and stringWidth(candidate, font_name, font_size) > max_width:
                chunks.append(current_chunk)
                current_chunk = ch
            else:
                current_chunk = candidate
        if current_chunk:
            chunks.append(current_chunk)
        return chunks

    tokens: list[str] = []
    for word in text.split(" "):
        tokens.extend(split_oversized_token(word))

    lines: list[str] = []
    current = ""
    for token in tokens:
        candidate = f"{current} {token}".strip()
        if current and stringWidth(candidate, font_name, font_size) > max_width:
            lines.append(current)
            current = token
        else:
            current = candidate
    lines.append(current)
    return lines


def _draw_wrapped(
    c, x: float, y: float, text: str, font_name: str, font_size: float,
    max_width: float, line_height: float, page_top_y: float, bottom_margin: float,
) -> float:
    """Draws `text` at (x, y), wrapping onto extra lines via _wrap_line and
    starting a new page (continuing at page_top_y, same font) if a line
    would land below bottom_margin. Returns the y position after the last
    line drawn, so callers keep using this file's existing top-down,
    y -= line_height layout."""
    for line in _wrap_line(text, font_name, font_size, max_width):
        if y < bottom_margin:
            c.showPage()
            c.setFont(font_name, font_size)
            y = page_top_y
        c.drawString(x, y, line)
        y -= line_height
    return y


# Shown verbatim in the PDF's "How to read this report" section and as
# report_notes in the JSON export -- one list, so the two outputs can
# never say something different about the same report.
REPORT_NOTES = [
    "Times are shown in the local time zone of the machine that produced this report.",
    "A session's start time is when Vigil first observed that agent in its current run. It can be later than when the agent actually started.",
    "Most file events carry the time the activity happened. Events from the polling fallback are timed when Vigil recorded them, which can be 5 to 20 seconds later.",
    "Events are counted by their own time. Sessions are listed if they overlap this period, so a session that began earlier can contribute events here.",
    "Vigil records only while it is running. Periods when it was not running, for example when the computer was asleep, are listed under Monitoring coverage in this report.",
]

# A gap at or above this duration is listed individually in the
# "Monitoring coverage" section; anything shorter (a quick restart, a
# rebuild-and-relaunch) is folded into one summary line instead, so a
# machine that restarted several times in a day doesn't get a report
# dominated by near-instant gaps. This is a display decision only --
# core/monitoring_coverage.py stores every gap regardless of duration.
SHORT_GAP_DISPLAY_THRESHOLD_SECONDS = 60


def _parse_utc(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


def _sql_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _format_duration_hm(seconds: float) -> str:
    total_minutes = int(seconds // 60)
    hours, minutes = divmod(total_minutes, 60)
    return f"{hours}h {minutes}m"


def _format_duration_ms(seconds: float) -> str:
    total_seconds = int(seconds)
    minutes, secs = divmod(total_seconds, 60)
    return f"{minutes}m {secs}s"


async def _compute_coverage(
    db, period_start_utc: datetime, period_end_utc: datetime, generated_at_utc: datetime,
) -> dict:
    """How much of this report's period Vigil was actually running, and
    every gap inside the measured span. The measured span is clipped on
    both ends: it never extends past "now" (generated_at) -- a report
    generated mid-day can't measure time that hasn't happened yet -- and
    it never starts before the earliest vigil_runs.started_at ever
    recorded, since there is no coverage data at all before coverage
    tracking itself began. coverage_available=False means nothing in
    this period is measurable at all (no run has ever been recorded, or
    every run started at or after the point we're measuring up to)."""
    measured_end = min(period_end_utc, generated_at_utc)

    cur = await db.execute("SELECT MIN(started_at) m FROM vigil_runs")
    row = await cur.fetchone()
    tracking_started_at = _parse_utc(row["m"]) if row and row["m"] else None

    if tracking_started_at is None or tracking_started_at >= measured_end:
        return {
            "coverage_available": False,
            "tracking_started_at": tracking_started_at.isoformat() if tracking_started_at else None,
            "active_seconds": 0,
            "period_seconds_measured": 0,
            "gaps": [],
            "short_gap_count": 0,
            "short_gap_seconds": 0,
        }

    measured_start = max(period_start_utc, tracking_started_at)
    period_seconds_measured = max(0.0, (measured_end - measured_start).total_seconds())

    cur = await db.execute(
        "SELECT gap_start, gap_end, reason FROM monitoring_gaps "
        "WHERE gap_start < ? AND gap_end > ? ORDER BY gap_start ASC",
        (_sql_ts(measured_end), _sql_ts(measured_start)),
    )
    rows = await cur.fetchall()

    gaps = []
    short_gap_count = 0
    short_gap_seconds = 0.0
    gap_seconds_total = 0.0
    for gap_row in rows:
        g_start = max(_parse_utc(gap_row["gap_start"]), measured_start)
        g_end = min(_parse_utc(gap_row["gap_end"]), measured_end)
        duration = (g_end - g_start).total_seconds()
        if duration <= 0:
            continue
        gap_seconds_total += duration
        if duration >= SHORT_GAP_DISPLAY_THRESHOLD_SECONDS:
            gaps.append({
                "start": g_start.isoformat(), "end": g_end.isoformat(),
                "duration_seconds": duration, "reason": gap_row["reason"],
            })
        else:
            short_gap_count += 1
            short_gap_seconds += duration

    active_seconds = max(0.0, period_seconds_measured - gap_seconds_total)

    return {
        "coverage_available": True,
        "tracking_started_at": tracking_started_at.isoformat(),
        "active_seconds": active_seconds,
        "period_seconds_measured": period_seconds_measured,
        "gaps": gaps,
        "short_gap_count": short_gap_count,
        "short_gap_seconds": short_gap_seconds,
    }


async def _build_summary(date: str, tz=None) -> dict:
    db = await get_db()
    day = _resolve_local_day(date, tz)
    start_utc, end_utc = _local_day_bounds_utc(day, tz)
    # DB timestamps are naive UTC strings -- same format the rest of the
    # codebase already queries against (see main.py's /api/stats).
    start_sql = start_utc.strftime("%Y-%m-%d %H:%M:%S")
    end_sql = end_utc.strftime("%Y-%m-%d %H:%M:%S")

    # Overlap, not "started inside this period": started_at < end (it
    # began before the period closed) AND (still open, or it ended at or
    # after the period opened). A session that started yesterday and is
    # still running (or only just ended) this morning has real events in
    # today's report -- excluding it from the Sessions list, as a plain
    # started_at-in-range filter did, meant the report could count a
    # session's events without ever listing that session.
    cur = await db.execute(
        "SELECT * FROM sessions WHERE started_at < ? AND (ended_at IS NULL OR ended_at >= ?)",
        (end_sql, start_sql),
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

    generated_at_utc = datetime.now(timezone.utc)
    coverage = await _compute_coverage(db, start_utc, end_utc, generated_at_utc)

    return {
        # Always the resolved real calendar date, never the literal
        # string "today" -- this is also what drives the download
        # filenames below, so "today" never leaks into a saved file name.
        "date": day.isoformat(),
        "generated_at": generated_at_utc.isoformat(),
        "period_start": start_utc.isoformat(),
        "period_end": end_utc.isoformat(),
        "timezone": start_utc.astimezone(tz).strftime("%Z") if tz is not None else start_utc.astimezone().strftime("%Z"),
        "event_count": event_count,
        "sessions": sessions,
        "alerts": alerts,
        "report_notes": REPORT_NOTES,
        **coverage,
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
    margin = inch
    max_width = width - 2 * margin
    page_top_y = height - margin

    def draw(y, text, font_name, font_size, line_height):
        return _draw_wrapped(c, margin, y, text, font_name, font_size, max_width, line_height, page_top_y, margin)

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
    generated_label = f"Generated: {_format_local(summary['generated_at'])}"

    y = page_top_y
    c.setFont("Helvetica-Bold", 16)
    y = draw(y, "Vigil Audit Report", "Helvetica-Bold", 16, 0.3 * inch)

    c.setFont("Helvetica", 10)
    # Period and Generated each get their own line -- a long zone name
    # (e.g. "India Standard Time" rather than "IST") combined with the
    # Generated timestamp on one line was wide enough to run past the
    # page margin.
    y = draw(y, period_label, "Helvetica", 10, 0.2 * inch)
    y = draw(y, generated_label, "Helvetica", 10, 0.3 * inch)
    y = draw(
        y,
        f"Events: {summary['event_count']}  Sessions: {len(summary['sessions'])}  Alerts: {len(summary['alerts'])}",
        "Helvetica", 10, 0.4 * inch,
    )

    from core.evidence_chain import verify_chain
    # verify_chain() opens its own dedicated connection internally.
    chain_result = await verify_chain()
    chain_status = "VERIFIED INTACT" if chain_result["valid"] else f"INTEGRITY FAILURE: {chain_result['reason']}"
    c.setFont("Helvetica-Bold", 10)
    y = draw(
        y, f"Evidence chain: {chain_status} ({chain_result['checked_count']} events checked)",
        "Helvetica-Bold", 10, 0.3 * inch,
    )

    period_start_utc = datetime.fromisoformat(summary["period_start"])

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Sessions", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    for session in summary["sessions"]:
        operator = f"{session.get('operator_username') or 'unknown'}@{session.get('operator_hostname') or 'unknown'}"
        ended_label = _format_local(session["ended_at"]) if session.get("ended_at") else "ongoing"
        line = (
            f"{session['id'][:8]}  operator={operator}  "
            f"started={_format_local(session['started_at'])}  ended={ended_label}"
        )
        session_started_utc = datetime.fromisoformat(
            session["started_at"].replace(" ", "T")
        ).replace(tzinfo=timezone.utc)
        if session_started_utc < period_start_utc:
            line += "  (began before this period)"
        y = draw(y, line, "Helvetica", 9, 0.2 * inch)
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Alerts", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    for alert in summary["alerts"]:
        line = f"[{alert['severity'].upper()}] {alert['title']} (status={alert['status']})"
        y = draw(y, line, "Helvetica", 9, 0.2 * inch)
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Monitoring coverage", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    if not summary["coverage_available"]:
        if summary["tracking_started_at"] is not None:
            tracking_started_local = datetime.fromisoformat(summary["tracking_started_at"]).astimezone()
            y = draw(
                y,
                f"Coverage was not recorded before {tracking_started_local.strftime('%d %b %Y %H:%M')} "
                "(local); this entire report period is before that.",
                "Helvetica", 9, 0.2 * inch,
            )
        else:
            y = draw(y, "Coverage was not recorded for any part of this period.", "Helvetica", 9, 0.2 * inch)
    else:
        active_seconds = summary["active_seconds"]
        period_seconds_measured = summary["period_seconds_measured"]
        percent = (active_seconds / period_seconds_measured * 100) if period_seconds_measured > 0 else 0.0
        y = draw(
            y,
            f"Vigil active: {_format_duration_hm(active_seconds)} of "
            f"{_format_duration_hm(period_seconds_measured)} ({percent:.1f}%)",
            "Helvetica", 9, 0.2 * inch,
        )

        tracking_started_at_utc = datetime.fromisoformat(summary["tracking_started_at"])
        if tracking_started_at_utc > period_start_utc:
            tracking_started_local = tracking_started_at_utc.astimezone()
            y = draw(
                y,
                f"Coverage was not recorded before {tracking_started_local.strftime('%d %b %Y %H:%M')} (local).",
                "Helvetica", 9, 0.2 * inch,
            )

        for gap in summary["gaps"]:
            gap_start_local = datetime.fromisoformat(gap["start"]).astimezone()
            gap_end_local = datetime.fromisoformat(gap["end"]).astimezone()
            line = (
                f"{gap_start_local.strftime('%d %b %Y %H:%M')} to {gap_end_local.strftime('%d %b %Y %H:%M')} "
                f"({_format_duration_hm(gap['duration_seconds'])}) - {gap['reason']}"
            )
            y = draw(y, line, "Helvetica", 9, 0.2 * inch)

        if summary["short_gap_count"] > 0:
            plural = "s" if summary["short_gap_count"] != 1 else ""
            y = draw(
                y,
                f"{summary['short_gap_count']} short restart{plural}, "
                f"total {_format_duration_ms(summary['short_gap_seconds'])}",
                "Helvetica", 9, 0.2 * inch,
            )
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "How to read this report", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    for note in summary["report_notes"]:
        y = draw(y, note, "Helvetica", 9, 0.2 * inch)

    c.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vigil-report-{summary['date']}.pdf"},
    )
