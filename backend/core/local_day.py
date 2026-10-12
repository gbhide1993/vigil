"""The machine's local calendar day, as UTC bounds in the stored format.

Events, alerts and sessions are stored as naive UTC strings. "Today" on the
dashboard must be the same local day the daily report uses (api/export.py), not
the UTC day: in a zone ahead of UTC the two disagree for the first hours of
every local day. This module reuses the export helpers so the two cannot drift.
"""

from datetime import timedelta

_SQL_FORMAT = "%Y-%m-%d %H:%M:%S"


def local_tz():
    """None means this machine's own timezone. Tests patch this to pin a zone
    (Windows has no tzset())."""
    return None


def local_day_window(days_ago: int = 0) -> tuple[str, str]:
    """(start, end) of the local calendar day `days_ago` days back, as stored
    UTC strings: start inclusive, end exclusive."""
    import api.export as export

    tz = local_tz()
    day = export._resolve_local_day("today", tz) - timedelta(days=days_ago)
    start_utc, end_utc = export._local_day_bounds_utc(day, tz)
    return start_utc.strftime(_SQL_FORMAT), end_utc.strftime(_SQL_FORMAT)
