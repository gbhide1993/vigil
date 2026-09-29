import asyncio
import time


class BurstDetector:
    """
    Sliding-window file-change burst detector.
    A burst = >= BURST_THRESHOLD events within BURST_WINDOW_SECS.
    """
    BURST_THRESHOLD = 10
    BURST_WINDOW_SECS = 60
    MIN_BURST_SIZE = 5

    def __init__(self):
        self._events: list[dict] = []
        self._lock = asyncio.Lock()

    async def record_event(self, path: str, event_type: str):
        now = time.time()
        async with self._lock:
            self._events.append({"timestamp": now, "path": path, "event_type": event_type})
            cutoff = now - self.BURST_WINDOW_SECS
            self._events = [e for e in self._events if e["timestamp"] >= cutoff]

    async def flush_burst(self) -> dict | None:
        """Returns burst dict if window qualifies, else None. Clears on return."""
        async with self._lock:
            if len(self._events) < self.MIN_BURST_SIZE:
                return None
            burst = {
                "start_time": self._events[0]["timestamp"],
                "end_time": self._events[-1]["timestamp"],
                "event_count": len(self._events),
                "files": list({e["path"] for e in self._events}),
            }
            self._events.clear()
            return burst
