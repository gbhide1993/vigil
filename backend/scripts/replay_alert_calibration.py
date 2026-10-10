"""Replays session-level alert scoring over a COPY of a Vigil database,
comparing the old logic with the calibrated logic (core/activity_filter.py).

Usage:
    python scripts/replay_alert_calibration.py <path-to-db-COPY> [--days N] [--list-limit N]

The database is only read (all work is SELECTs), and the script refuses to
run on the live database path. Copy the live files first, including
vlaw.db-wal and vlaw.db-shm, and point this script at the copy.

What is recomputed: the Layer 2a threshold, time and ratio alerts, the
Layer 2b rolling alerts, the unknown-destination alerts (old: one per
distinct unrecognised destination per session; new: only destinations not
seen by an earlier non-resumed session of the same agent in the last 30
days) and the checkpoint alerts (old: the ones already in the database;
new: none). Uncorroborated unusual-hour sessions and repeat destinations are
counted as report info lines, not alerts. Everything else (red-line and
policy alerts) is not recomputed by either side and is reported as
"unchanged" from the alerts table, so the totals compare like with like.

Network corroboration in the new logic is recomputed too: a session counts
as network-corroborated if it has a first-seen unrecognised destination or
a low-severity red-line destination alert, not because of an old-logic
unknown-destination alert row.

Not modelled: Alerter dedup windows and open-duplicate suppression (both
sides are shown without them), and the live "which alerts were open" state.
"""

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("VLAW_DATA_DIR", tempfile.mkdtemp(prefix="vlaw_replay_"))

import aiosqlite  # noqa: E402

from core.activity_filter import (  # noqa: E402
    MIN_HISTORY_SESSIONS, cap_severity, evaluate_prior_volume, evaluate_rolling_volume,
    get_corroboration, session_volume_metrics, SEVERITY_ORDER,
)
from core.layer2a import unknown_destination_split, unusual_hour_label  # noqa: E402
from core.layer2b import MAD_THRESHOLD, mad_score  # noqa: E402
from core.priors import get_prior  # noqa: E402


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace(" ", "T")).replace(tzinfo=timezone.utc)


def _local_tz():
    return datetime.now().astimezone().tzinfo


# --------------------------------------------------------------- old logic

async def old_session_metrics(db, sid, agent_id):
    async def count(types):
        marks = ",".join("?" * len(types))
        cur = await db.execute(
            f"SELECT COUNT(*) c FROM events WHERE session_id = ? AND agent_id = ? AND event_type IN ({marks})",
            (sid, agent_id, *types),
        )
        return (await cur.fetchone())["c"]

    cur = await db.execute("SELECT started_at, ended_at FROM sessions WHERE id = ?", (sid,))
    row = await cur.fetchone()
    duration = 0.0
    if row and row["started_at"] and row["ended_at"]:
        duration = (_parse(row["ended_at"]) - _parse(row["started_at"])).total_seconds()
    return {
        "file": await count(("file_read", "file_write")),
        "network": await count(("net_connect",)),
        "process": await count(("proc_spawn",)),
        "duration": duration,
    }


def old_2a_threshold(metrics, prior):
    out = []
    for key, pkey, label in (("file", "file_events_per_session", "file events"),
                             ("network", "network_events_per_session", "network connections"),
                             ("process", "process_spawns_per_session", "processes")):
        th = prior[pkey]
        v = metrics[key]
        if v <= th["high"]:
            continue
        sev = "critical" if v >= th["critical"] else "high"
        out.append((sev, "volumetric_threshold", f"{label}: {v}"))
    return out


async def old_time_anomaly(db, sess, agent_id, prior):
    start_utc = _parse(sess["started_at"])
    hour = start_utc.astimezone(_local_tz()).hour
    lo, hi = prior["normal_hours"]
    if lo <= hour < hi:
        return []
    cur = await db.execute(
        "SELECT ended_at FROM sessions WHERE agent_id = ? AND id != ? AND ended_at IS NOT NULL AND ended_at < ? "
        "ORDER BY ended_at DESC LIMIT 1",
        (agent_id, sess["id"], sess["started_at"]),
    )
    last = await cur.fetchone()
    sev = "high"
    if last is not None and (start_utc - _parse(last["ended_at"])).total_seconds() / 3600 > 4:
        sev = "critical"
    return [(sev, "time_anomaly", f"started at local hour {hour}")]


def old_2b(current, history):
    if len(history) < 3:
        return []
    out = []
    for key, label in (("file", "files"), ("network", "network connections"),
                       ("process", "processes"), ("duration", "session duration")):
        values = [h[key] for h in history]
        median = sorted(values)[len(values) // 2]
        if current[key] <= median:
            continue
        score = mad_score(current[key], values)
        if score <= MAD_THRESHOLD:
            continue
        out.append(("high" if score > 6.0 else "medium", "rolling_anomaly", f"{label}: {current[key]} vs median {median:.0f}"))
    return out


async def has_low_red_line(db, sid, aid) -> bool:
    cur = await db.execute(
        "SELECT 1 FROM alerts WHERE agent_id = ? AND rule_type = 'red_line' AND severity = 'low' "
        "AND (session_id = ? OR event_id IN (SELECT id FROM events WHERE session_id = ?)) LIMIT 1",
        (aid, sid, sid),
    )
    return await cur.fetchone() is not None


# --------------------------------------------------------------------- main

async def main(db_path: str, days: int | None, list_limit: int) -> int:
    live = Path(os.environ.get("LOCALAPPDATA", "")) / "V-LAW" / "data" / "vlaw.db"
    if live.exists() and Path(db_path).resolve() == live.resolve():
        print("Refusing to run on the live database. Copy vlaw.db (+ -wal and -shm) and pass the copy.")
        return 2

    db = await aiosqlite.connect(db_path)
    db.row_factory = aiosqlite.Row
    try:
        cur = await db.execute(
            "SELECT s.id, s.agent_id, s.started_at, s.ended_at, s.resumed, a.name AS agent_name "
            "FROM sessions s LEFT JOIN agents a ON a.id = s.agent_id "
            "WHERE s.ended_at IS NOT NULL ORDER BY s.ended_at ASC"
        )
        sessions = [dict(r) for r in await cur.fetchall()]

        old_metrics, new_metrics = {}, {}
        for s in sessions:
            old_metrics[s["id"]] = await old_session_metrics(db, s["id"], s["agent_id"])
            new_metrics[s["id"]] = await session_volume_metrics(db, s["id"], s["agent_id"])

        old_alerts, new_alerts = [], []   # (session, severity, kind, description)
        info_hour, info_repeat = [], []   # report info lines that replace alerts: (session, text)
        by_agent_old = defaultdict(list)  # chronological closed sessions per agent (old history)
        by_agent_new = defaultdict(list)

        for s in sessions:
            sid, aid = s["id"], s["agent_id"]
            prior = get_prior(s["agent_name"])
            new_dests, repeat_dests = await unknown_destination_split(sid, aid, prior, db)
            corro = await get_corroboration(db, sid, aid)
            corro.network = (await has_low_red_line(db, sid, aid)) or bool(new_dests)

            # ---- old
            cur_old = old_metrics[sid]
            for sev, kind, desc in old_2a_threshold(cur_old, prior):
                old_alerts.append((s, sev, kind, desc))
            for sev, kind, desc in await old_time_anomaly(db, s, aid, prior):
                old_alerts.append((s, sev, kind, desc))
            for dest in new_dests + repeat_dests:
                old_alerts.append((s, "medium", "unknown_destination", dest))
            if not s["resumed"]:
                hist_old = []
                for h in reversed(by_agent_old[aid]):
                    hm = old_metrics[h]
                    if hm["file"] == 0 and hm["network"] == 0 and hm["duration"] == 0:
                        continue
                    hist_old.append(hm)
                    if len(hist_old) >= 5:
                        break
                for sev, kind, desc in old_2b(cur_old, hist_old):
                    old_alerts.append((s, sev, kind, desc))

            # ---- new
            nm = new_metrics[sid]
            contributions = evaluate_prior_volume(nm, prior)
            if not s["resumed"]:
                hist_new = []
                for h in reversed(by_agent_new[aid]):
                    hm = new_metrics[h]
                    if hm["file_writes"] == 0 and hm["network"] == 0 and old_metrics[h]["duration"] == 0:
                        continue
                    hist_new.append(hm)
                    if len(hist_new) >= 7:
                        break
                if len(hist_new) >= MIN_HISTORY_SESSIONS:
                    contributions += evaluate_rolling_volume(nm, hist_new, mad_score, MAD_THRESHOLD)
            if contributions:
                base = max((c.base_severity for c in contributions), key=lambda x: SEVERITY_ORDER[x])
                desc = "; ".join(c.detail for c in contributions)
                if corro.any:
                    desc += f" [corroborated by: {', '.join(corro.names())}]"
                new_alerts.append((s, cap_severity(base, corro), "volume_anomaly", desc))
            for sev, kind, desc in await old_time_anomaly(db, s, aid, prior):
                if corro.any:
                    new_alerts.append((s, cap_severity(sev, corro), kind, f"{desc} [corroborated by: {', '.join(corro.names())}]"))
                elif not s["resumed"]:
                    info_hour.append((s, f"started at an unusual hour: {unusual_hour_label(s['started_at'], s['agent_name'])} local"))
            for dest in new_dests:
                new_alerts.append((s, "medium", "unknown_destination", dest))
            if repeat_dests:
                info_repeat.append((s, f"{len(repeat_dests)} repeat unrecognised destination(s)"))

            if not s["resumed"]:  # history only ever contains non-resumed sessions
                by_agent_old[aid].append(sid)
                by_agent_new[aid].append(sid)

        # ---- window
        if days:
            cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
            keep = lambda s: _parse(s["ended_at"]).timestamp() >= cutoff  # noqa: E731
            old_alerts = [a for a in old_alerts if keep(a[0])]
            new_alerts = [a for a in new_alerts if keep(a[0])]
            info_hour = [a for a in info_hour if keep(a[0])]
            info_repeat = [a for a in info_repeat if keep(a[0])]
            window_clause = " AND created_at >= datetime('now', ?)"
            window_args = (f"-{days} days",)
            scope = f"last {days} days"
        else:
            window_clause, window_args, scope = "", (), "all history"

        # ---- unchanged categories, straight from the alerts table
        cur = await db.execute(
            "SELECT rule_type, severity, COUNT(*) n FROM alerts WHERE 1=1" + window_clause +
            " GROUP BY rule_type, severity", window_args,
        )
        table = [dict(r) for r in await cur.fetchall()]
        checkpoint_old = sum(r["n"] for r in table if r["rule_type"] == "checkpoint_activity")
        recomputed_types = {"volumetric_threshold", "rolling_anomaly", "time_anomaly", "ratio_anomaly",
                            "checkpoint_activity", "volume_anomaly", "unknown_destination"}
        unchanged = [r for r in table if r["rule_type"] not in recomputed_types]
        unknown_dest_in_table = sum(r["n"] for r in table if r["rule_type"] == "unknown_destination")

        def sev_counts(rows, key=lambda r: r[1]):
            c = Counter(key(r) for r in rows)
            return {k: c.get(k, 0) for k in ("critical", "high", "medium", "low")}

        old_by_sev = sev_counts(old_alerts)
        new_by_sev = sev_counts(new_alerts)
        old_by_sev["low"] += checkpoint_old
        unchanged_by_sev = Counter()
        for r in unchanged:
            unchanged_by_sev[r["severity"]] += r["n"]
        unchanged_sev = {k: unchanged_by_sev.get(k, 0) for k in ("critical", "high", "medium", "low")}

        print(f"Replay over a copy of the database ({scope}); {len(sessions)} closed sessions scored overall.")
        print()
        print("Recomputed alerts, old logic vs new logic (no dedup modelled):")
        print(f"  {'severity':10} {'old':>6} {'new':>6}")
        for sev in ("critical", "high", "medium", "low"):
            print(f"  {sev:10} {old_by_sev[sev]:>6} {new_by_sev[sev]:>6}")
        print(f"  {'total':10} {sum(old_by_sev.values()):>6} {sum(new_by_sev.values()):>6}"
              f"   (old includes {checkpoint_old} checkpoint alerts, new has 0)")
        print()
        print("By type, old -> new:")
        old_types = Counter(a[2] for a in old_alerts)
        new_types = Counter(a[2] for a in new_alerts)
        old_types["checkpoint_activity"] = checkpoint_old
        for t in sorted(set(old_types) | set(new_types)):
            print(f"  {t:22} {old_types.get(t, 0):>6} -> {new_types.get(t, 0):>6}")
        print()
        print(f"Unknown-destination alerts: {unknown_dest_in_table} exist in the alerts table for this window; "
              f"old logic recomputed {sum(1 for a in old_alerts if a[2] == 'unknown_destination')}, "
              f"new logic {sum(1 for a in new_alerts if a[2] == 'unknown_destination')} "
              f"(distinct destinations covered: {len({a[3] for a in old_alerts if a[2] == 'unknown_destination'})}).")
        print(f"Report info lines instead of alerts: {len(info_hour)} unusual-hour sessions, "
              f"{len(info_repeat)} sessions with repeat unrecognised destinations "
              f"({sum(int(t.split()[0]) for _, t in info_repeat)} destinations).")
        print()
        print("Not recomputed (identical before and after; red-line and policy alerts):")
        for r in sorted(unchanged, key=lambda r: (-r["n"], r["rule_type"])):
            print(f"  {r['rule_type']:24} {r['severity']:9} {r['n']:>6}")
        print(f"  total unchanged by severity: {unchanged_sev}")
        print()
        print("All alerts, old and new combined with the unchanged ones:")
        for sev in ("critical", "high", "medium", "low"):
            print(f"  {sev:10} old {old_by_sev[sev] + unchanged_sev[sev]:>6}   new {new_by_sev[sev] + unchanged_sev[sev]:>6}")
        day_set = {a[0]["ended_at"][:10] for a in new_alerts}
        print()
        print(f"Remaining recomputed alerts ({len(new_alerts)}), every one listed (limit {list_limit}):")
        for s, sev, kind, desc in sorted(new_alerts, key=lambda a: a[0]["ended_at"])[:list_limit]:
            print(f"  {s['ended_at'][:16]}  {sev:8} {kind:15} {s['agent_name']:12} {s['id'][:8]}  {desc}")
        if len(new_alerts) > list_limit:
            print(f"  ... {len(new_alerts) - list_limit} more (raise --list-limit)")
        if days:
            print(f"\nDistinct days with a remaining recomputed alert: {len(day_set)}")
            print(f"Unusual-hour info lines in this window ({len(info_hour)}):")
            for s, text in sorted(info_hour, key=lambda a: a[0]["ended_at"])[:list_limit]:
                print(f"  {s['ended_at'][:16]}  {s['agent_name']:12} {s['id'][:8]}  {text}")
            skip = ",".join("?" * len(recomputed_types))
            cur = await db.execute(
                "SELECT created_at, severity, rule_type, title FROM alerts "
                f"WHERE rule_type NOT IN ({skip}) AND created_at >= datetime('now', ?) ORDER BY created_at",
                (*sorted(recomputed_types), f"-{days} days"),
            )
            rows = await cur.fetchall()
            print(f"Remaining alerts that were not recomputed (red-line and policy), {len(rows)} in this window:")
            for r in rows[:list_limit]:
                print(f"  {r['created_at'][:16]}  {r['severity']:8} {r['rule_type']:12} {r['title'][:110]}")
        return 0
    finally:
        await db.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("db_copy")
    ap.add_argument("--days", type=int, default=None, help="only count sessions that ended in the last N days")
    ap.add_argument("--list-limit", type=int, default=500)
    ns = ap.parse_args()
    sys.exit(asyncio.run(main(ns.db_copy, ns.days, ns.list_limit)))
