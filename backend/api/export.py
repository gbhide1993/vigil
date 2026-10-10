import io
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from db.database import get_db

router = APIRouter()


def _format_local(ts: str) -> str:
    """Parse a stored UTC timestamp (naive 'YYYY-MM-DD HH:MM:SS' or an
    isoformat string with an explicit offset) and format it in the
    system's local timezone. No zone name/offset suffix here -- the
    Period line at the top of the report states the offset once (see
    _utc_offset_label); repeating a long zone name on every single time
    in the report added width for no new information."""
    dt = datetime.fromisoformat(ts.replace(" ", "T"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _utc_offset_label(dt: datetime) -> str:
    """"UTC+05:30" / "UTC-04:00" style label for an aware datetime's
    local UTC offset, used once on the Period line instead of a long
    zone name repeated on every time in the report."""
    offset = dt.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours, minutes = divmod(total_minutes, 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


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
    "The evidence chain check covers the events table only. It does not cover alerts, dismissals, policy, sessions or monitoring coverage. Vigil runs the check itself on its own database, and no copy of the chain is held anywhere else, so it shows that the stored events are consistent with each other, not that they could not have been rewritten.",
    "Vigil records files being created, changed, moved or deleted. It does not record files being read.",
    "Alert times are when Vigil detected the issue. After a restart this can be later than the activity itself.",
    "Vigil checks which programs are running about every 30 seconds. A program that starts and finishes between checks is not recorded. For recorded programs the command text is shown, with common secret patterns (passwords, tokens, keys) replaced by [REDACTED] on a best-effort basis, so very unusual secrets may still appear.",
]

# Alerts whose description ends in the spawned command line (see
# RedLines.check_dangerous_command and ProcessWatcher's generic
# "Suspicious command spawned" alert). The command is already redacted at
# capture, so the PDF just echoes it from the description.
_COMMAND_ALERT_REASONS = {"red_line_dangerous_command", "suspicious_command"}
_COMMAND_IN_DESCRIPTION = re.compile(r"(?:sensitive|suspicious) command: (.+)", re.DOTALL)
_PDF_COMMAND_MAX_CHARS = 200


def _alert_command_line(alert: dict) -> str | None:
    if alert.get("reason") not in _COMMAND_ALERT_REASONS:
        return None
    m = _COMMAND_IN_DESCRIPTION.search(alert.get("description") or "")
    if not m:
        return None
    command = " ".join(m.group(1).split())
    if len(command) > _PDF_COMMAND_MAX_CHARS:
        command = command[:_PDF_COMMAND_MAX_CHARS] + "..."
    return command

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


def _format_duration(seconds: float) -> str:
    """"Xh Ym" for an hour or more, "Xm Ys" under an hour -- "0h 5m" for a
    five-minute gap loses the only precision that distinguishes it from
    a near-instant one, so anything under an hour shows seconds instead
    of a second hour-scale unit that would always read 0."""
    total_seconds = int(seconds)
    if total_seconds < 3600:
        minutes, secs = divmod(total_seconds, 60)
        return f"{minutes}m {secs}s"
    hours, remainder = divmod(total_seconds, 3600)
    minutes = remainder // 60
    return f"{hours}h {minutes}m"


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


# Used only to pick the "highest" severity when grouping a session's
# alerts together in the PDF (see _draw_alerts_grouped_by_session) --
# higher number wins.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


async def _draw_alerts_grouped_by_session(draw, y: float, summary: dict) -> float:
    """PDF-only: groups summary["alerts"] by session_id into one header
    line per session ("Session <id8> (<agent>): N alerts, highest
    <SEVERITY>, detected <local time>") followed by one indented line per
    alert, instead of one flat line per alert. Alerts with no session_id
    fall into a final "Other alerts" group, rendered exactly as the flat
    list used to be. The JSON export is untouched by this -- it stays
    one flat row per alert, raw evidence, no grouping.

    A session referenced by an alert but not present in this report's
    own Sessions section (the alert fired today, but the session itself
    ended before this period -- see the resumed-session investigation:
    a session recovered and scored at the next startup carries that
    startup's timestamp on its alerts, not its own) gets a direct
    lookup here for its agent name and real ended_at, so the group
    header can still say which agent it was and why it isn't listed
    above."""
    from reportlab.lib.units import inch

    alerts = summary["alerts"]
    if not alerts:
        return y

    sessions_in_report = {s["id"]: s for s in summary["sessions"]}

    by_session: dict[str, list[dict]] = {}
    other_alerts: list[dict] = []
    for alert in alerts:
        session_id = alert.get("session_id")
        if session_id:
            by_session.setdefault(session_id, []).append(alert)
        else:
            other_alerts.append(alert)

    missing_ids = set(by_session.keys()) - set(sessions_in_report.keys())
    extra_session_info: dict[str, dict] = {}
    if missing_ids:
        db = await get_db()
        placeholders = ",".join("?" * len(missing_ids))
        cur = await db.execute(
            f"SELECT s.id, s.ended_at, a.name as agent_name FROM sessions s "
            f"LEFT JOIN agents a ON a.id = s.agent_id WHERE s.id IN ({placeholders})",
            tuple(missing_ids),
        )
        for row in await cur.fetchall():
            extra_session_info[row["id"]] = dict(row)

    # Oldest group first, matching the flat list's previous chronological order.
    ordered_session_ids = sorted(by_session.keys(), key=lambda sid: min(a["created_at"] for a in by_session[sid]))

    for session_id in ordered_session_ids:
        group = sorted(by_session[session_id], key=lambda a: a["created_at"])
        highest = max(group, key=lambda a: _SEVERITY_RANK.get(a["severity"], 0))
        detected_local = _format_local(group[0]["created_at"])

        out_of_period_suffix = ""
        if session_id in sessions_in_report:
            agent_name = sessions_in_report[session_id].get("agent_name") or "unidentified_agent"
        else:
            info = extra_session_info.get(session_id, {})
            agent_name = info.get("agent_name") or "unidentified_agent"
            ended_at = info.get("ended_at")
            if ended_at:
                ended_local = datetime.fromisoformat(ended_at.replace(" ", "T")).replace(
                    tzinfo=timezone.utc
                ).astimezone()
                out_of_period_suffix = f" (session ended {ended_local.strftime('%d %b %H:%M:%S')}, before this period)"

        plural = "s" if len(group) != 1 else ""
        header = (
            f"Session {session_id[:8]} ({agent_name}): {len(group)} alert{plural}, "
            f"highest {highest['severity'].upper()}, detected {detected_local}{out_of_period_suffix}"
        )
        y = draw(y, header, "Helvetica-Bold", 9, 0.2 * inch)
        for alert in group:
            line = f"[{alert['severity'].upper()}] {alert['title']} (status={alert['status']})"
            y = draw(y, line, "Helvetica", 9, 0.2 * inch, indent=0.3 * inch)
            command = _alert_command_line(alert)
            if command:
                y = draw(y, command, "Helvetica", 8, 0.18 * inch, indent=0.6 * inch)

    if other_alerts:
        y = draw(y, "Other alerts", "Helvetica-Bold", 9, 0.2 * inch)
        for alert in sorted(other_alerts, key=lambda a: a["created_at"]):
            prefix = _format_local(alert["created_at"])
            line = f"{prefix}  [{alert['severity'].upper()}] {alert['title']} (status={alert['status']})"
            y = draw(y, line, "Helvetica", 9, 0.2 * inch)
            command = _alert_command_line(alert)
            if command:
                y = draw(y, command, "Helvetica", 8, 0.18 * inch, indent=0.3 * inch)

    return y


async def _checkpoint_counts_by_session(db, start_sql: str, end_sql: str) -> dict[str, int]:
    """Writes into Claude's hidden file-history (checkpoint) folder, per
    session. These used to raise one low "checkpoint write" alert per burst;
    they are normal /rewind activity, so the report now shows a single info
    line per session instead (see RedLines.check_claude_cache_write)."""
    from core.red_lines import is_claude_cache_write

    cur = await db.execute(
        "SELECT session_id, path, file_count FROM events "
        "WHERE event_type = 'file_write' AND created_at >= ? AND created_at < ? "
        "AND (path LIKE '%file-history%')",
        (start_sql, end_sql),
    )
    counts: dict[str, int] = {}
    for row in await cur.fetchall():
        if is_claude_cache_write(row["path"] or ""):
            counts[row["session_id"]] = counts.get(row["session_id"], 0) + (row["file_count"] or 1)
    return counts


async def _sessions_with_time_alert(db, session_ids: list[str]) -> set[str]:
    if not session_ids:
        return set()
    marks = ",".join("?" * len(session_ids))
    cur = await db.execute(
        f"SELECT DISTINCT session_id FROM alerts WHERE reason = 'time_anomaly' AND session_id IN ({marks})",
        tuple(session_ids),
    )
    return {row["session_id"] for row in await cur.fetchall()}


async def _add_calibration_info(db, session: dict, time_alerted: set[str]) -> None:
    """Facts that used to be (noisy) alerts and are now report info lines:

    - unusual_hour: "23:40" (local) when the session started outside the
      agent's normal hours and no time-anomaly alert was raised for it
      (an alert needs a corroborating signal, see Layer 2a). Not set for
      resumed sessions: their started_at is when Vigil began watching,
      not when the agent started.
    - repeat_unknown_destinations: how many unrecognised destinations the
      session used that an earlier session of the same agent already used
      within 30 days (no alert is raised for those).
    """
    from core.layer2a import unknown_destination_split, unusual_hour_label
    from core.priors import get_prior

    agent_name = session.get("agent_name") or ""
    session["unusual_hour"] = None
    if not session.get("resumed") and session["id"] not in time_alerted and session.get("started_at"):
        session["unusual_hour"] = unusual_hour_label(session["started_at"], agent_name)

    session["repeat_unknown_destinations"] = 0
    if session.get("agent_id") is not None:
        _new, repeat = await unknown_destination_split(session["id"], session["agent_id"], get_prior(agent_name), db)
        session["repeat_unknown_destinations"] = len(repeat)


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
        """
        SELECT s.*, a.name as agent_name FROM sessions s
        LEFT JOIN agents a ON a.id = s.agent_id
        WHERE s.started_at < ? AND (s.ended_at IS NULL OR s.ended_at >= ?)
        """,
        (end_sql, start_sql),
    )
    sessions = [dict(r) for r in await cur.fetchall()]

    # One aggregated pass over events, not one COUNT(*) per session --
    # same reasoning as every other per-row count in this codebase
    # (see e.g. api/sessions.py's net_connect_count). Scoped to this
    # period's events only, matching what each session line displays.
    cur = await db.execute(
        "SELECT session_id, COUNT(*) c FROM events WHERE created_at >= ? AND created_at < ? GROUP BY session_id",
        (start_sql, end_sql),
    )
    event_counts_by_session = {row["session_id"]: row["c"] for row in await cur.fetchall()}
    checkpoint_counts = await _checkpoint_counts_by_session(db, start_sql, end_sql)
    time_alerted = await _sessions_with_time_alert(db, [s["id"] for s in sessions])
    for session in sessions:
        session["event_count_in_period"] = event_counts_by_session.get(session["id"], 0)
        session["checkpoint_writes"] = checkpoint_counts.get(session["id"], 0)
        await _add_calibration_info(db, session, time_alerted)
        # A session whose started_at/ended_at are identical and which
        # contributed no events this period is the artifact a restart
        # produces (see the duplicate-session investigation): opened and
        # immediately closed with nothing ever having happened in it.
        # Listing dozens of these individually buries the sessions that
        # actually did something, so they're folded into one count
        # instead -- the JSON keeps every row (no_activity marks which).
        session["no_activity"] = (
            session["ended_at"] is not None
            and session["started_at"] == session["ended_at"]
            and session["event_count_in_period"] == 0
        )
        # resumed=1 means ProcessWatcher's first poll after a restart
        # rediscovered an already-running process (core/sessions.py::touch)
        # -- its started_at is when Vigil started watching, not when the
        # agent actually started. Still listed (not folded like no_activity
        # sessions above): a resumed session can carry real activity after
        # the rediscovery, just not a real start time. bool() so the JSON
        # export reads resumed: true/false, not the raw 0/1 column value.
        session["resumed"] = bool(session["resumed"])

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


CHAIN_SCOPE = (
    "Covers the events table only, not alerts, dismissals, policy, sessions or coverage. "
    "Checked by Vigil itself; not externally anchored."
)


async def _chain_verification() -> dict:
    """Runs verify_chain() (which opens its own dedicated connection) and
    shapes the result for the exports. Shared by the JSON and PDF outputs
    so they cannot word the same check differently."""
    from core.evidence_chain import verify_chain

    result = await verify_chain()
    consistent = bool(result["valid"])
    return {
        "status": "consistent" if consistent else "inconsistent",
        "events_checked": result["checked_count"],
        "first_bad_event_id": None if consistent else result.get("first_bad_event_id"),
        "scope": CHAIN_SCOPE,
    }


def _chain_header_text(chain: dict) -> str:
    if chain["status"] == "consistent":
        return (
            f"Evidence chain: consistent ({chain['events_checked']} events checked). "
            "Checked by Vigil itself; not yet independently anchored."
        )
    bad = chain["first_bad_event_id"]
    where = f"event {bad}" if bad is not None else "an unknown event"
    return f"Evidence chain: INCONSISTENT at {where}. Do not rely on this report."


@router.get("/export/json")
async def export_json(date: str = Query(default="today")):
    summary = await _build_summary(date)
    summary["chain_verification"] = await _chain_verification()
    return summary


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

    def draw(y, text, font_name, font_size, line_height, indent=0.0):
        # indent shifts the actual draw x-position, rather than
        # prepending spaces to text -- _wrap_line's token-rejoin pass
        # (`f"{current} {token}".strip()`) strips leading whitespace from
        # the very first token, so a literal "    (marker)" string always
        # loses its indent once it goes through word-wrapping.
        # Set the font on every call: _draw_wrapped measures and wraps with
        # font_name/font_size but only calls setFont itself on a page break,
        # so without this a line is drawn in whatever font the previous
        # section left active (e.g. alert rows in the bold heading font) and
        # can run past the width it was wrapped for.
        c.setFont(font_name, font_size)
        return _draw_wrapped(
            c, margin + indent, y, text, font_name, font_size, max_width - indent, line_height, page_top_y, margin,
        )

    # period_start/period_end are UTC ISO; converting each back to local
    # time for display here (rather than storing a pre-formatted string in
    # the summary) keeps _build_summary's return value machine-readable
    # for the JSON export and lets the PDF format it however it needs to.
    period_start_local = datetime.fromisoformat(summary["period_start"]).astimezone()
    period_end_local = datetime.fromisoformat(summary["period_end"]).astimezone()
    period_label = (
        f"Period: {period_start_local.strftime('%d %b %Y %H:%M')} to "
        f"{period_end_local.strftime('%d %b %Y %H:%M')} ({_utc_offset_label(period_start_local)})"
    )
    generated_label = f"Generated: {_format_local(summary['generated_at'])}"

    y = page_top_y
    c.setFont("Helvetica-Bold", 16)
    y = draw(y, "Vigil Audit Report", "Helvetica-Bold", 16, 0.3 * inch)

    c.setFont("Helvetica", 10)
    # Period and Generated each get their own line -- combining them was
    # wide enough to run past the page margin even before the offset
    # label was added.
    y = draw(y, period_label, "Helvetica", 10, 0.2 * inch)
    y = draw(y, generated_label, "Helvetica", 10, 0.3 * inch)

    active_sessions = [s for s in summary["sessions"] if not s["no_activity"]]
    no_activity_sessions = [s for s in summary["sessions"] if s["no_activity"]]
    sessions_summary = f"Sessions: {len(active_sessions)}"
    if no_activity_sessions:
        sessions_summary += f" (+{len(no_activity_sessions)} with no recorded activity)"
    y = draw(
        y,
        f"Events: {summary['event_count']}  {sessions_summary}  Alerts: {len(summary['alerts'])}",
        "Helvetica", 10, 0.4 * inch,
    )

    chain = await _chain_verification()
    c.setFont("Helvetica-Bold", 10)
    y = draw(y, _chain_header_text(chain), "Helvetica-Bold", 10, 0.3 * inch)

    period_start_utc = datetime.fromisoformat(summary["period_start"])

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Sessions", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    for session in active_sessions:
        operator = f"{session.get('operator_username') or 'unknown'}@{session.get('operator_hostname') or 'unknown'}"
        ended_label = _format_local(session["ended_at"]) if session.get("ended_at") else "ongoing"
        agent_name = session.get("agent_name") or "unidentified_agent"
        line = (
            f"{session['id'][:8]}  agent={agent_name}  operator={operator}  "
            f"started={_format_local(session['started_at'])}  ended={ended_label}  "
            f"events={session['event_count_in_period']}"
        )
        y = draw(y, line, "Helvetica", 9, 0.2 * inch)
        # Each marker always starts its own indented line rather than
        # being appended to the (already long) main line -- appending
        # left it at the mercy of _wrap_line's width-driven wrapping,
        # which could split the marker's own words across two sub-lines
        # depending on locale/zone-name width.
        session_started_utc = datetime.fromisoformat(
            session["started_at"].replace(" ", "T")
        ).replace(tzinfo=timezone.utc)
        if session_started_utc < period_start_utc:
            y = draw(y, "(began before this period)", "Helvetica", 9, 0.2 * inch, indent=0.3 * inch)
        if session["resumed"]:
            y = draw(y, "(already running when Vigil started)", "Helvetica", 9, 0.2 * inch, indent=0.3 * inch)
        if session.get("unusual_hour"):
            y = draw(
                y, f"(info: started at an unusual hour: {session['unusual_hour']} local)",
                "Helvetica", 9, 0.2 * inch, indent=0.3 * inch,
            )
        if session.get("repeat_unknown_destinations"):
            n = session["repeat_unknown_destinations"]
            y = draw(
                y,
                f"(info: {n} unrecognised destination{'s' if n != 1 else ''} also used by earlier sessions "
                "within 30 days, not alerted again)",
                "Helvetica", 9, 0.2 * inch, indent=0.3 * inch,
            )
        if session.get("checkpoint_writes"):
            n = session["checkpoint_writes"]
            y = draw(
                y,
                f"(info: {n} checkpoint write{'s' if n != 1 else ''} to the agent's hidden cache folder, normal /rewind activity)",
                "Helvetica", 9, 0.2 * inch, indent=0.3 * inch,
            )
    if no_activity_sessions:
        plural = "s" if len(no_activity_sessions) != 1 else ""
        y = draw(
            y, f"{len(no_activity_sessions)} session{plural} with no recorded activity",
            "Helvetica", 9, 0.2 * inch,
        )
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Alerts", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    y = await _draw_alerts_grouped_by_session(draw, y, summary)
    y -= 0.2 * inch

    c.setFont("Helvetica-Bold", 12)
    y = draw(y, "Monitoring coverage", "Helvetica-Bold", 12, 0.25 * inch)
    c.setFont("Helvetica", 9)
    # %H:%M:%S here, not %H:%M -- the stored value already has whole-
    # second precision (no sub-second rounding happens anywhere in this
    # display), so showing seconds exactly is what keeps this time from
    # ever reading as earlier than the real tracking start.
    if not summary["coverage_available"]:
        if summary["tracking_started_at"] is not None:
            tracking_started_local = datetime.fromisoformat(summary["tracking_started_at"]).astimezone()
            y = draw(
                y,
                f"Coverage was not recorded before {tracking_started_local.strftime('%d %b %Y %H:%M:%S')} "
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
            f"Vigil active: {_format_duration(active_seconds)} of "
            f"{_format_duration(period_seconds_measured)} ({percent:.1f}%)",
            "Helvetica", 9, 0.2 * inch,
        )

        tracking_started_at_utc = datetime.fromisoformat(summary["tracking_started_at"])
        if tracking_started_at_utc > period_start_utc:
            tracking_started_local = tracking_started_at_utc.astimezone()
            y = draw(
                y,
                f"Coverage was not recorded before {tracking_started_local.strftime('%d %b %Y %H:%M:%S')} (local).",
                "Helvetica", 9, 0.2 * inch,
            )

        for gap in summary["gaps"]:
            gap_start_local = datetime.fromisoformat(gap["start"]).astimezone()
            gap_end_local = datetime.fromisoformat(gap["end"]).astimezone()
            line = (
                f"{gap_start_local.strftime('%d %b %Y %H:%M:%S')} to "
                f"{gap_end_local.strftime('%d %b %Y %H:%M:%S')} "
                f"({_format_duration(gap['duration_seconds'])}) - {gap['reason']}"
            )
            y = draw(y, line, "Helvetica", 9, 0.2 * inch)

        if summary["short_gap_count"] > 0:
            plural = "s" if summary["short_gap_count"] != 1 else ""
            y = draw(
                y,
                f"{summary['short_gap_count']} short restart{plural}, "
                f"total {_format_duration(summary['short_gap_seconds'])}",
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
