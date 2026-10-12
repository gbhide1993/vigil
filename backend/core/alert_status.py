"""The one definition of "how worried should the dashboard look".

Used by /api/stats (which feeds the Status page, the sidebar badge and the
tray tooltip), so all three agree by construction. Old open alerts no longer
drive the headline: only what was detected in the last 24 hours does.

  red    at least one open HIGH or CRITICAL alert detected in the last 24 hours
  amber  no such alert, but at least one open MEDIUM alert in the last 24 hours
  green  otherwise

Open alerts older than 24 hours (medium or above) are counted separately as
older_open and shown as a quiet line, never as part of the headline. Low
severity alerts never change the status.
"""

WINDOW_HOURS = 24


async def alert_status_counts(db) -> dict:
    window = f"-{WINDOW_HOURS} hours"
    cur = await db.execute(
        """
        SELECT
            COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') AND created_at >= datetime('now', ?)
                              THEN 1 ELSE 0 END), 0) AS recent_high,
            COALESCE(SUM(CASE WHEN severity = 'medium' AND created_at >= datetime('now', ?)
                              THEN 1 ELSE 0 END), 0) AS recent_medium,
            COALESCE(SUM(CASE WHEN severity IN ('medium', 'high', 'critical') AND created_at < datetime('now', ?)
                              THEN 1 ELSE 0 END), 0) AS older_open,
            COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END), 0) AS high_total
        FROM alerts
        WHERE status = 'open'
        """,
        (window, window, window),
    )
    row = await cur.fetchone()
    return {
        "needs_review": row["recent_high"],
        "open_medium_24h": row["recent_medium"],
        "older_open": row["older_open"],
        "needs_review_total": row["high_total"],
    }


def status_level(counts: dict) -> str:
    if counts["needs_review"] > 0:
        return "red"
    if counts["open_medium_24h"] > 0:
        return "amber"
    return "green"
