from fastapi import APIRouter

from db.database import get_db

router = APIRouter()


@router.get("/digest/daily")
async def get_daily_digest():
    db = await get_db()

    cur = await db.execute(
        "SELECT COUNT(*) c FROM alerts WHERE created_at > datetime('now', '-24 hours')"
    )
    alerts_24h = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts
        WHERE created_at > datetime('now', '-24 hours') AND rule_type = 'red_line'
        """
    )
    red_line_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT COUNT(*) c FROM alerts
        WHERE created_at > datetime('now', '-24 hours')
          AND rule_type IN ('volumetric_threshold', 'time_anomaly', 'ratio_anomaly', 'unknown_destination')
        """
    )
    anomaly_count = (await cur.fetchone())["c"]

    cur = await db.execute(
        """
        SELECT DISTINCT a.name FROM sessions s
        JOIN agents a ON a.id = s.agent_id
        WHERE s.started_at > datetime('now', '-24 hours')
           OR s.ended_at > datetime('now', '-24 hours')
           OR (s.ended_at IS NULL AND s.started_at IS NOT NULL)
        ORDER BY a.name
        """
    )
    agent_rows = await cur.fetchall()
    agent_names = [row["name"] for row in agent_rows]
    agents_active = len(agent_names)

    clean = alerts_24h == 0

    if clean:
        summary = "All clear. No alerts in the last 24 hours."
    else:
        summary = f"{alerts_24h} alert{'s' if alerts_24h != 1 else ''} in the last 24h."
        if red_line_count:
            summary += f" {red_line_count} RED LINE."
        if agent_names:
            summary += f" {', '.join(agent_names)} active."
        if anomaly_count:
            summary += f" {anomaly_count} behavioral anomaly detected."
        summary = summary[:100]

    return {
        "alerts_24h": alerts_24h,
        "red_line_count": red_line_count,
        "agents_active": agents_active,
        "clean": clean,
        "summary": summary,
    }
