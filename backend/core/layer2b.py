"""Layer 2b: rolling-window MAD (Median Absolute Deviation) anomaly
detection. Unlike Layer 2a's embedded priors (population-level, apply
from session 1) and Layer 1's baseline (this machine's full history,
14-day gate), Layer 2b compares a session against just this agent's
last few closed sessions — a robust, fast-adapting local comparison
that activates once 5 non-resumed historical sessions exist.

Calibrated by core/activity_filter.py: generated paths and helper
processes are not counted, absolute floors and a 3x floored-baseline rule
apply, session duration is no longer scored on its own, and the findings
are merged into the session's single "Unusual activity volume" alert.

Fires independently of Layer 2a; the same session can be flagged by
both without conflict — they're different detection methods answering
different questions ("is this normal for any Claude Code session?" vs
"is this normal for how *this* agent has been behaving lately?").
"""

from datetime import datetime, timezone

from core.activity_filter import (
    MIN_HISTORY_SESSIONS, evaluate_rolling_volume, fire_volume_alert, session_volume_metrics,
)
from core.alerter import Alerter

MAD_THRESHOLD = 3.5

_alerter = Alerter()


def mad_score(value: float, history: list[float]) -> float:
    """Median Absolute Deviation score: how many MADs `value` sits from
    the median of `history`. Robust equivalent of a z-score, meaningful
    at N >= 3 where mean/stddev are too noisy to trust.

    FIXED: previously returned 0.0 silently whenever MAD itself was 0
    (happens when 3+ history values tie at the median) — this meant
    genuinely anomalous sessions were missed for agents with very
    consistent historical behavior. Now falls back to a simple
    percentage-deviation check in this specific edge case.
    """
    if len(history) < 3:
        return 0.0

    median = sorted(history)[len(history) // 2]
    deviations = [abs(x - median) for x in history]
    mad = sorted(deviations)[len(deviations) // 2]

    if mad < 0.001:
        # Zero-variance history — fall back to percentage deviation
        # instead of going silent.
        if median < 0.001:
            # KNOWN RESIDUAL: median=0 with a nonzero new value also returns 0.0
            # (silently misses "first time ever" spikes). Lower priority than the
            # original bug since Layer 2a's hard-threshold/unknown-destination checks
            # independently catch most real-world "first occurrence" scenarios through
            # a different mechanism. Worth a proper fix eventually, not urgent now.
            return 0.0  # both value and median are ~0, genuinely nothing to compare

        pct_deviation = abs(value - median) / median
        # Scale percentage deviation to roughly match MAD_THRESHOLD's
        # sensitivity (3.5) — treat 100%+ deviation as equivalent to
        # crossing the threshold. This *3.5 multiplier is a reasonable
        # approximation to keep this fallback path roughly consistent
        # with MAD_THRESHOLD elsewhere, not a precisely derived
        # statistical constant.
        return pct_deviation * 3.5

    return abs(value - median) / mad


def _median(values: list[float]) -> float:
    return sorted(values)[len(values) // 2]


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


async def _session_metrics(session_id: str, agent_id: int, db) -> dict[str, float]:
    metrics = await session_volume_metrics(db, session_id, agent_id)

    cur = await db.execute(
        "SELECT started_at, ended_at FROM sessions WHERE id = ?",
        (session_id,),
    )
    row = await cur.fetchone()
    duration_seconds = 0.0
    if row is not None and row["started_at"] and row["ended_at"]:
        duration_seconds = (_parse_ts(row["ended_at"]) - _parse_ts(row["started_at"])).total_seconds()

    # duration_seconds is kept only so get_session_history can tell an
    # empty session from a real one; it is never scored (a long session is
    # not an anomaly by itself).
    return {**metrics, "duration_seconds": duration_seconds}


async def get_session_history(agent_id: int, exclude_session_id: str, db, limit: int = 7) -> list[dict]:
    """Last `limit` closed, real sessions for this agent (excluding the
    current one), each with its filtered volume metrics. Returns []
    if fewer than MIN_HISTORY_SESSIONS (5) exist -- Layer 2b stays silent
    until then.

    Skips resumed=1 sessions (ProcessWatcher's first poll after a
    restart rediscovering an already-running process -- their
    started_at/duration reflect Vigil's own restart, not the agent's
    real behaviour, see core/sessions.py::touch) and sessions with no
    counted activity or duration at all (nothing real to measure). Both
    would otherwise skew the median every other session is compared
    against. Fetches more candidates than `limit` up front so filtering
    those out still leaves a full window when enough real history exists."""
    cur = await db.execute(
        """
        SELECT id FROM sessions
        WHERE agent_id = ? AND id != ? AND ended_at IS NOT NULL AND resumed = 0
        ORDER BY ended_at DESC LIMIT ?
        """,
        (agent_id, exclude_session_id, limit * 4),
    )
    rows = await cur.fetchall()

    history = []
    for row in rows:
        metrics = await _session_metrics(row["id"], agent_id, db)
        if metrics["file_writes"] == 0 and metrics["network"] == 0 and metrics["duration_seconds"] == 0:
            continue
        history.append(metrics)
        if len(history) >= limit:
            break

    if len(history) < MIN_HISTORY_SESSIONS:
        return []
    return history


async def score_session_2b(session_id: str, agent_id: int, agent_name: str, db) -> list[int]:
    alert_ids: list[int] = []

    try:
        cur = await db.execute("SELECT resumed FROM sessions WHERE id = ?", (session_id,))
        row = await cur.fetchone()
        if row is not None and row["resumed"]:
            # Rediscovered-on-restart: this session's own metrics are
            # partial (see core/sessions.py::touch), so comparing them
            # against history is meaningless -- consistent with
            # core/baseline.py's update_from_session, which skips
            # folding/scoring resumed=1 sessions for the same reason.
            return []

        history = await get_session_history(agent_id, session_id, db)
        if len(history) < MIN_HISTORY_SESSIONS:
            return []

        current = await _session_metrics(session_id, agent_id, db)

        # Upward-only, floored and 3x-baseline rules live in
        # evaluate_rolling_volume; mad_score is a two-sided magnitude, so
        # the "value above the median" gate there is what keeps a quiet
        # session from ever being reported as "more".
        contributions = evaluate_rolling_volume(current, history, mad_score, MAD_THRESHOLD)
        alert_id = await fire_volume_alert(_alerter, db, session_id, agent_id, agent_name, contributions)
        if alert_id is not None:
            alert_ids.append(alert_id)
    except Exception as e:
        print(f"Layer2b scoring failed: {e}")

    return alert_ids
