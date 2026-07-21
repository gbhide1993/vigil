"""Local usage analytics for Vigil.

Append-only JSONL file at ~/.vigil/usage.jsonl. Never transmitted
anywhere. Used only for local behavior analysis during the beta period
to understand which features are actually used.

No personal data. No file contents. No paths. No credentials. Ever.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

ANALYTICS_PATH = Path.home() / ".vigil" / "usage.jsonl"
_lock = asyncio.Lock()


async def track(event: str, properties: dict | None = None) -> None:
    """Append a single usage event to the local analytics log. Fails
    silently — analytics must never affect product behavior."""
    try:
        entry = {
            "event": event,
            "ts": datetime.now(timezone.utc).isoformat(),
            **{k: v for k, v in (properties or {}).items() if v is not None},
        }
        ANALYTICS_PATH.parent.mkdir(parents=True, exist_ok=True)
        async with _lock:
            with open(ANALYTICS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
