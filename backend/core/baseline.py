"""Layer 1 statistical baseline. Passive — never blocks or alters
behavior on its own. Only activates alerting (LOW anomaly alerts) once
policy.baseline_days_required has been met for a given agent."""

import json
import math
from datetime import datetime, timedelta, timezone

from core.alerter import Alerter
from db.database import get_db

METRIC_NAMES = (
    "file_read_count",
    "file_write_count",
    "net_egress_mb",
    "proc_spawn_count",
    "session_duration_minutes",
)


class Baseline:
    def __init__(self):
        self.alerter = Alerter()

    async def update_from_session(self, session_id: str) -> None:
        """Called when a session completes. Pulls the session's summary
        stats and folds them into that agent's running baseline using
        Welford's online mean/variance update, then scores the session
        against the baseline it just updated."""
        db = await get_db()

        cur = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = await cur.fetchone()
        if session is None:
            return

        agent_id = session["agent_id"]
        duration_minutes = self._session_duration_minutes(session)

        metrics = {
            "file_read_count": session["file_reads"],
            "file_write_count": session["file_writes"],
            "net_egress_mb": session["net_egress_bytes"] / (1024 * 1024),
            "proc_spawn_count": session["proc_spawns"],
            "session_duration_minutes": duration_minutes,
        }

        for metric_name, value in metrics.items():
            await self._update_metric(db, agent_id, metric_name, scope=None, value=value)

        await self._update_top_directories(db, agent_id, session_id)

        await db.commit()

        anomaly_score = await self.calculate_anomaly_score(agent_id, metrics)

        await db.execute(
            "UPDATE sessions SET anomaly_score = ? WHERE id = ?",
            (anomaly_score, session_id),
        )
        await db.commit()

        baseline_active = await self._is_baseline_active(db, agent_id)
        if baseline_active and anomaly_score > 0.7:
            await self.alerter.check_anomaly_score(agent_id, session_id, anomaly_score)

    async def _update_metric(self, db, agent_id: int, metric_name: str, scope: str | None, value: float) -> None:
        """Welford's online algorithm — updates mean/stddev incrementally
        without needing to store the full history of samples."""
        cur = await db.execute(
            """
            SELECT sample_count, mean_value, stddev_value, min_value, max_value
            FROM baseline WHERE agent_id = ? AND metric_name = ? AND metric_scope IS ?
            """,
            (agent_id, metric_name, scope),
        )
        row = await cur.fetchone()

        if row is None:
            await db.execute(
                """
                INSERT INTO baseline
                    (agent_id, metric_name, metric_scope, sample_count, mean_value, stddev_value, min_value, max_value)
                VALUES (?, ?, ?, 1, ?, 0, ?, ?)
                """,
                (agent_id, metric_name, scope, value, value, value),
            )
            return

        n = row["sample_count"]
        old_mean = row["mean_value"]
        old_m2 = (row["stddev_value"] ** 2) * n

        new_n = n + 1
        delta = value - old_mean
        new_mean = old_mean + delta / new_n
        delta2 = value - new_mean
        new_m2 = old_m2 + delta * delta2
        new_stddev = math.sqrt(new_m2 / new_n) if new_n > 0 else 0.0

        new_min = min(row["min_value"], value) if row["min_value"] is not None else value
        new_max = max(row["max_value"], value) if row["max_value"] is not None else value

        await db.execute(
            """
            UPDATE baseline
            SET sample_count = ?, mean_value = ?, stddev_value = ?, min_value = ?, max_value = ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE agent_id = ? AND metric_name = ? AND metric_scope IS ?
            """,
            (new_n, new_mean, new_stddev, new_min, new_max, agent_id, metric_name, scope),
        )

    async def _update_top_directories(self, db, agent_id: int, session_id: str) -> None:
        """Tracks per-directory access counts as a scoped metric so the
        top 10 directories per agent can be derived from the baseline
        table (metric_name='dir_access_count', metric_scope=<dir path>)."""
        cur = await db.execute(
            """
            SELECT path, SUM(file_count) as total
            FROM events
            WHERE agent_id = ? AND session_id = ? AND event_type IN ('file_read', 'file_write')
            GROUP BY path
            """,
            (agent_id, session_id),
        )
        rows = await cur.fetchall()
        for row in rows:
            await self._update_metric(db, agent_id, "dir_access_count", scope=row["path"], value=row["total"])

    async def calculate_anomaly_score(self, agent_id: int, metrics: dict[str, float]) -> float:
        """Z-score each metric against its baseline, then average the
        top 3 |Z| scores and squash into 0.0-1.0 via a bounded normalization."""
        db = await get_db()
        z_scores: list[float] = []

        for metric_name, value in metrics.items():
            cur = await db.execute(
                """
                SELECT sample_count, mean_value, stddev_value
                FROM baseline WHERE agent_id = ? AND metric_name = ? AND metric_scope IS NULL
                """,
                (agent_id, metric_name),
            )
            row = await cur.fetchone()
            if row is None or row["sample_count"] < 2 or row["stddev_value"] == 0:
                continue

            z = abs((value - row["mean_value"]) / row["stddev_value"])
            z_scores.append(z)

        if not z_scores:
            return 0.0

        z_scores.sort(reverse=True)
        top3 = z_scores[:3]
        mean_top3 = sum(top3) / len(top3)

        # squash: z=0 -> 0.0, z>=4 -> ~1.0
        return min(1.0, mean_top3 / 4.0)

    async def _is_baseline_active(self, db, agent_id: int) -> bool:
        cur = await db.execute(
            "SELECT policy_value FROM policy WHERE policy_key = 'baseline_days_required'"
        )
        row = await cur.fetchone()
        days_required = json.loads(row["policy_value"]) if row else 14

        cur = await db.execute("SELECT first_seen FROM agents WHERE id = ?", (agent_id,))
        agent_row = await cur.fetchone()
        if agent_row is None:
            return False

        first_seen = datetime.fromisoformat(agent_row["first_seen"]).replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - first_seen >= timedelta(days=days_required)

    def _session_duration_minutes(self, session) -> float:
        if session["ended_at"] is None:
            return 0.0
        started = datetime.fromisoformat(session["started_at"])
        ended = datetime.fromisoformat(session["ended_at"])
        return (ended - started).total_seconds() / 60.0
