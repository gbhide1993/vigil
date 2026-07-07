"""Day-one insight cards. Cheap SQL aggregates over events/agents that
are useful before an agent's 14-day baseline has matured — Layer 1's
z-score anomaly detection is silent until then, but a user launching
V-LAW for the first time shouldn't stare at an empty dashboard for two
weeks. These are plain facts, not anomalies: no statistics, no
baseline dependency, just "what happened today" framed usefully.
"""

from db.database import get_db


async def get_insights() -> dict:
    db = await get_db()

    cur = await db.execute(
        """
        SELECT fp.path, fp.agent_id, a.name as agent_name, fp.first_seen
        FROM (
            SELECT path, agent_id, MIN(created_at) as first_seen
            FROM events
            WHERE path IS NOT NULL
            GROUP BY path
            HAVING date(first_seen) = date('now')
        ) fp
        LEFT JOIN agents a ON a.id = fp.agent_id
        ORDER BY fp.first_seen DESC
        LIMIT 1
        """
    )
    first_time_dir = await cur.fetchone()

    cur = await db.execute(
        """
        SELECT e.path, e.agent_id, a.name as agent_name, e.file_count
        FROM events e
        LEFT JOIN agents a ON a.id = e.agent_id
        WHERE e.event_type = 'file_write' AND date(e.created_at) = date('now')
        ORDER BY e.file_count DESC
        LIMIT 1
        """
    )
    largest_write = await cur.fetchone()

    cur = await db.execute(
        """
        SELECT COUNT(DISTINCT path) c FROM events
        WHERE path IS NOT NULL AND date(created_at) = date('now')
        """
    )
    directory_diversity = (await cur.fetchone())["c"]

    cur = await db.execute(
        "SELECT COUNT(DISTINCT agent_id) c FROM events WHERE date(created_at) = date('now')"
    )
    agent_diversity = (await cur.fetchone())["c"]

    cards = []

    if first_time_dir is not None:
        cards.append({
            "kind": "first_time_directory",
            "text": f"{first_time_dir['agent_name'] or 'An agent'} touched {first_time_dir['path']} for the first time today.",
            "detail": {"path": first_time_dir["path"], "agent_name": first_time_dir["agent_name"]},
        })

    if largest_write is not None and largest_write["file_count"]:
        count = largest_write["file_count"]
        cards.append({
            "kind": "largest_write",
            "text": f"{largest_write['agent_name'] or 'An agent'} wrote {count} file{'s' if count != 1 else ''} to {largest_write['path']} in a single burst — the largest write today.",
            "detail": {"path": largest_write["path"], "agent_name": largest_write["agent_name"], "file_count": count},
        })

    cards.append({
        "kind": "directory_diversity",
        "text": f"Agents touched {directory_diversity} distinct director{'y' if directory_diversity == 1 else 'ies'} today.",
        "detail": {"count": directory_diversity},
    })

    cards.append({
        "kind": "agent_diversity",
        "text": f"{agent_diversity} agent{'s' if agent_diversity != 1 else ''} {'were' if agent_diversity != 1 else 'was'} active today.",
        "detail": {"count": agent_diversity},
    })

    return {"cards": cards}
