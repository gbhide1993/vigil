import json

from fastapi import APIRouter

from core.analytics import ANALYTICS_PATH, track

router = APIRouter()

# Whitelist of events the frontend may report — never log arbitrary
# strings from the browser. digest_sent and alert_resolved are backend-
# only (fired from digest_api.py / alerts.py directly), not reachable
# through this endpoint.
ALLOWED_TRACK_EVENTS = {
    "dashboard_open",
    "view_changed",
    "incident_viewed",
    "query_used",
    "export_clicked",
}


def _read_events() -> list[dict]:
    if not ANALYTICS_PATH.exists():
        return []
    events = []
    with open(ANALYTICS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                continue
    return events


@router.get("/analytics/summary")
async def analytics_summary():
    events = _read_events()
    if not events:
        return {"total_events": 0, "message": "No usage data yet"}

    by_type: dict[str, int] = {}
    for e in events:
        name = e.get("event")
        if name:
            by_type[name] = by_type.get(name, 0) + 1

    timestamps = [e["ts"] for e in events if "ts" in e]
    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None

    days_active = 0
    if first and last:
        from datetime import datetime

        d1 = datetime.fromisoformat(first.replace("Z", "+00:00"))
        d2 = datetime.fromisoformat(last.replace("Z", "+00:00"))
        days_active = max(1, (d2 - d1).days + 1)

    # dashboard_open/view_changed both carry a flattened "view" property
    # (see track() — properties are spread onto the entry, not nested).
    views = [
        e.get("view")
        for e in events
        if e.get("event") in ("dashboard_open", "view_changed") and e.get("view")
    ]
    most_used = max(set(views), key=views.count) if views else None

    webhook_configured = any(
        e.get("webhook_configured") for e in events if e.get("event") == "digest_sent"
    )

    return {
        "total_events": len(events),
        "first_event": first,
        "last_event": last,
        "days_active": days_active,
        "events_by_type": by_type,
        "most_used_view": most_used,
        "queries_run": by_type.get("query_used", 0),
        "digests_sent": by_type.get("digest_sent", 0),
        "webhook_configured": webhook_configured,
    }


@router.post("/analytics/track")
async def track_event(body: dict):
    event = body.get("event", "")
    props = body.get("properties", {})
    if event not in ALLOWED_TRACK_EVENTS:
        return {"ok": False}
    await track(event, props)
    return {"ok": True}
