"""Polls the process tree every 3 seconds looking for new processes
spawned under a known agent. Process spawns are never aggregated —
each is logged individually and immediately."""

import asyncio
import json
import logging
import re
import sys
import time
from pathlib import Path

from core.alerter import Alerter
from core.attributor import KNOWN_AGENTS, Attributor
from core.feature_flags import CORE_ONLY
from core.red_lines import RedLines
from db.database import get_db

logger = logging.getLogger("vlaw")

POLL_INTERVAL_SECONDS = 3

# psutil holds the GIL for the duration of the underlying Windows API call
# (OpenProcess/ReadProcessMemory) during process_iter()/environ()/cmdline().
# A single slow or AV-intercepted handle open can hold the GIL long enough
# to freeze the *entire* process, including the asyncio event loop thread —
# at that point asyncio.timeout() cannot even fire, since firing it requires
# the event loop thread to run, which itself requires the GIL. Scanning in
# a subprocess sidesteps this entirely: the subprocess has its own GIL, so a
# stall there never blocks this process's event loop, and the subprocess can
# be hard-killed (proc.kill()) if it doesn't finish in time — something no
# amount of thread-pool/executor restructuring within this process can do,
# since a thread-pool-executor thread still shares this process's GIL.
_WORKER_PATH = str(Path(__file__).parent / "_process_scan_worker.py")
_SCAN_TIMEOUT_SECONDS = 18

# Separate, more generous bound for the post-scan DB-write phase (see
# poll()/_poll_write_phase) -- deliberately not the same 45s used for the
# scan. A cancellation landing mid db.execute()/commit() on the shared
# aiosqlite connection can leave that connection in a bad state for every
# other caller sharing it, so a slow-but-progressing write should be
# allowed to finish rather than get torn down on the scan's tighter
# cadence. This is a last-resort backstop for a genuinely wedged write,
# not a normal-case bound.
_POLL_WRITE_TIMEOUT_SECONDS = 90

# Pre-filter gate applied before any expensive per-process psutil call
# (environ()/cmdline() — on Windows these hold the GIL for the duration of
# the underlying OpenProcess/ReadProcessMemory syscall, so even off the
# event-loop thread they still stall it). Checked against the process's
# bare name (extension stripped) before environ()/cmdline() is ever called,
# so a box with hundreds of unrelated processes still only pays the
# expensive syscall cost for the handful that could plausibly be an agent.
AGENT_PROCESS_NAMES = {
    "python", "python3", "pythonw",
    "node", "node.exe",
    "cursor", "cursor.exe",
    "code", "code.exe",
    "claude", "claude.exe",
    "windsurf", "windsurf.exe",
    "zed", "zed.exe",
    "pycharm64", "idea64", "goland64",
    "bun", "bun.exe",
    "deno", "deno.exe",
}


def _strip_exe_suffix(name: str) -> str:
    return name[:-4] if name.endswith(".exe") else name


_AGENT_PROCESS_NAMES_STRIPPED = {_strip_exe_suffix(n) for n in AGENT_PROCESS_NAMES}


def _is_agent_process_name(name: str) -> bool:
    return _strip_exe_suffix((name or "").lower()) in _AGENT_PROCESS_NAMES_STRIPPED


# Matched against the executable's basename (argv[0]) or the "python -c"/
# "python3 -c" two-token form, never the full argv blob — a substring check
# against the whole cmdline false-positives constantly (e.g. "nc" inside
# "sync", "function", "--renderer-client-id", which every Electron
# subprocess spawn includes as flag text).
SUSPICIOUS_EXE_PATTERNS = {"curl", "wget", "ssh", "scp", "nc", "ncat"}
SUSPICIOUS_INLINE_PATTERNS = ["python -c", "python3 -c", "powershell -enc", "powershell -command"]

# Agent-config env vars checked by RL7 (core/red_lines.py::check_env_var_redirect).
# Kept here (not in red_lines.py) since this is the only place env vars are
# actually read off a live process.
RELEVANT_ENV_VARS = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY",
    "OPENAI_BASE_URL", "OPENAI_API_KEY",
}


def _match_known_agent_name(process_name: str) -> str | None:
    """Direct name match against core.attributor.KNOWN_AGENTS — deliberately
    does not walk the parent chain like Attributor.get_agent_for_pid does.
    RL7 needs the specific process whose own environment carries the
    redirected var, not whichever ancestor happens to be a known agent."""
    lowered = process_name.lower()
    for agent_key, process_names in KNOWN_AGENTS.items():
        if any(pn.lower() in lowered for pn in process_names):
            return agent_key
    return None


def _is_suspicious(cmdline: str, exe_basename: str) -> bool:
    exe = re.sub(r"\.(exe|bin)$", "", exe_basename.lower())
    if exe in SUSPICIOUS_EXE_PATTERNS:
        return True
    lowered = cmdline.lower()
    return any(pattern in lowered for pattern in SUSPICIOUS_INLINE_PATTERNS)


class ProcessWatcher:
    def __init__(self, attributor: Attributor, aggregator=None):
        self.attributor = attributor
        # Used to funnel the batched proc_spawn INSERT (see
        # _poll_write_body) through Aggregator's single-writer queue
        # instead of a bare get_db() call, so it can't collide with
        # Aggregator's own writes under SQLite WAL's single-writer-at-a-
        # time rule. Optional/None-checked at the call site so this class
        # still works if ever constructed without one (e.g. in a test).
        self.aggregator = aggregator
        self.alerter = Alerter()
        self.red_lines = RedLines()
        self._known_pids: set[int] = set()
        # PIDs _gather_spawn_info has already resolved to a non-None agent
        # name (includes "unidentified_agent") — lets
        # _scan_all_agent_processes_for_env_redirect re-check only PIDs
        # already known to be agent processes, and is also unioned into the
        # agent-candidate set _snapshot_pids asks the scan subprocess for
        # environ()/cmdline() data on each cycle (see _snapshot_pids).
        self._known_agent_pids: set[int] = set()
        # One-per-poll {pid: {"name", "ppid", "status"}} snapshot built by
        # _snapshot_pids from the scan subprocess's process list, and
        # passed to Attributor.get_agent_for_pid so its parent-chain walk
        # resolves from this dict instead of opening a fresh OS process
        # handle per level (see _walk_parent_chain_from_snapshot).
        self._pid_snapshot: dict[int, dict] = {}
        # {pid: env_dict} — rebuilt fresh every cycle for agent-process-
        # NAMED pids only (see _snapshot_pids), never cached across cycles:
        # RL7 (env-var-redirect detection) needs each such process's
        # *current* environment every time, not a stale first-seen copy.
        self._env_snapshot: dict[int, dict] = {}
        # {pid: {"args", "exe_path"}} — cached permanently per pid once
        # fetched (see _snapshot_pids): unlike env, a process's cmdline/exe
        # path can't change during its lifetime, so there's no freshness
        # requirement forcing a re-fetch. Both dicts are populated by
        # _snapshot_pids (via the scan subprocess — this process never
        # calls proc.environ()/proc.cmdline()/proc.exe() itself) and
        # consumed by _gather_spawn_info/_scan_all_agent_processes_for_env_redirect.
        self._cmdline_snapshot: dict[int, dict] = {}

    def stop(self) -> None:
        pass

    def get_snapshot(self) -> dict[int, dict]:
        """Read-only {pid: {name, ppid, env}} view for CorrelationEngine
        (core/correlation_engine.py) — reflects whatever the most recent
        _snapshot_pids call populated in self._pid_snapshot/
        self._env_snapshot, does not trigger a scan itself, and makes no
        psutil call of any kind. env is only ever populated for PIDs that
        were an agent candidate this cycle (see _snapshot_pids); every
        other PID reports an empty dict, matching the graceful-degradation
        behaviour already used elsewhere in this file."""
        return {
            pid: {
                "name": info.get("name", ""),
                "ppid": info.get("ppid", 0),
                "env": self._env_snapshot.get(pid, {}),
            }
            for pid, info in self._pid_snapshot.items()
        }

    async def poll(self) -> None:
        """Called periodically by the scheduler. Detects PIDs not seen in
        the previous poll and checks whether they were spawned under a
        known agent process tree, then independently re-scans every
        currently-running agent process for RL7 (see
        _scan_all_agent_processes_for_env_redirect) — that scan must not be
        gated behind "new PIDs this poll", since a redirect can be set on a
        process that was already running before this poll started.

        Every psutil call (process listing, and environ()/cmdline()/exe()
        for agent-related PIDs) runs in the scan subprocess (see
        _run_process_scan/_process_scan_worker.py), not in this process at
        all — no thread pool, no in-process psutil import. psutil holds the
        GIL for the duration of the underlying Windows API call
        (OpenProcess/ReadProcessMemory), so a single slow or AV-intercepted
        handle open can hold the GIL long enough to freeze this entire
        process — including the asyncio event loop thread that would
        otherwise fire this method's own asyncio.timeout. A
        thread-pool-executor thread doesn't help there, since it still
        shares this process's GIL. A subprocess has its own GIL and can be
        hard-killed (proc.kill()) if it doesn't finish within
        _SCAN_TIMEOUT_SECONDS, without touching this process at all.
        _gather_spawn_info/_scan_all_agent_processes_for_env_redirect are
        now pure Python dict access over that subprocess's results; only DB
        writes and alert firing (already async) stay on the loop.

        Also the heartbeat for core/monitoring_coverage.py's Monitoring
        coverage tracking (see record_coverage_tick() there, and the
        comment at this job's scheduler.add_job() call in main.py) --
        called first, before any of this method's own fallible scan
        logic, and fully self-contained (it never raises), so a coverage
        write failure can never affect this poll and a scan failure here
        can never suppress the heartbeat.

        The 45s timeout below covers ONLY the subprocess scan
        (_snapshot_pids) -- it deliberately does not wrap the DB-write phase
        that follows (_poll_write_phase). A cancellation landing mid
        db.execute()/commit() on the shared aiosqlite connection can leave
        that connection in a bad state for every other caller sharing it
        (Aggregator's writer task included), which is worse than letting a
        slow write finish late. The write phase gets its own, much more
        generous timeout instead -- see _poll_write_phase/
        _POLL_WRITE_TIMEOUT_SECONDS -- so a truly-stuck write is still
        eventually reported, just not torn down mid-transaction on the
        scan's tighter cadence."""
        from core.monitoring_coverage import record_coverage_tick
        await record_coverage_tick()

        try:
            async with asyncio.timeout(45):
                current_pids = await self._snapshot_pids()
        except TimeoutError:
            logger.warning("ProcessWatcher.poll scan timed out after 45s -- skipping cycle")
            return

        await self._poll_write_phase(current_pids)

    async def _poll_write_phase(self, current_pids: set[int]) -> None:
        """Bounds _poll_write_body with its own generous, separate timeout
        (see _POLL_WRITE_TIMEOUT_SECONDS) instead of poll()'s 45s scan
        timeout -- see poll()'s docstring for why the two are deliberately
        not the same bound. Logs loudly (not a silent skip) if this one
        fires, since by this point it means a DB write actually got stuck,
        not just a slow subprocess."""
        try:
            async with asyncio.timeout(_POLL_WRITE_TIMEOUT_SECONDS):
                await self._poll_write_body(current_pids)
        except TimeoutError:
            logger.error(
                "ProcessWatcher.poll write phase timed out after %ds -- "
                "this cycle's process-spawn events/alerts may be incomplete, "
                "and a stuck write on the shared DB connection may still be "
                "affecting other writers",
                _POLL_WRITE_TIMEOUT_SECONDS,
            )

    async def _poll_write_body(self, current_pids: set[int]) -> None:
        scan_failed = not current_pids
        if scan_failed:
            # Empty result means the scan subprocess timed out/failed this
            # cycle (see _run_process_scan), not that every process on the
            # box exited — never treat it as ground truth for spawn
            # detection. Leave self._known_pids untouched so the next
            # successful scan diffs against the last real baseline instead
            # of flagging every still-running PID as newly spawned. RL7
            # (env-redirect scan, below) is unaffected and still runs —
            # it re-checks self._known_agent_pids, which this cycle's
            # failure doesn't touch.
            new_pids = set()
        else:
            new_pids = current_pids - self._known_pids
            self._known_pids = current_pids

        logger.info("ProcessWatcher new_pids this cycle: %d", len(new_pids))

        env_redirect_hits = self._scan_all_agent_processes_for_env_redirect()
        for hit in env_redirect_hits:
            agent_id = await self.attributor.get_or_create_agent(hit["agent_name"], hit["pid"])
            session_id = await self.attributor.sessions.touch(agent_id)
            if not CORE_ONLY:
                await self.red_lines.check_env_var_redirect(
                    agent_id, hit["agent_name"], session_id, hit["agent_env"], pid=hit["pid"]
                )

        if not new_pids:
            return

        spawn_infos = await self._gather_spawn_info(new_pids)

        pending_rows: list[dict] = []

        for i, info in enumerate(spawn_infos):
            if i % 15 == 0:
                # Yield to the event loop periodically so a large cold-start
                # batch (e.g. every PID on the box, right after a restart --
                # see self._known_pids starting empty) can't starve HTTP
                # request handling or other scheduled jobs for this loop's
                # entire duration. Guarantees a scheduling point regardless
                # of how fast/slow the awaits below turn out to be.
                await asyncio.sleep(0)

            pid = info["pid"]
            cmdline = info["cmdline"]
            exe_name = info["exe_name"]
            exe_path = info["exe_path"]
            parent_pid = info["parent_pid"]
            agent_name = info["agent_name"]

            if agent_name is None:
                continue  # not under a known agent, and not agent-like by behaviour either

            is_unidentified = agent_name == "unidentified_agent"
            # get_behaviour_score_for_pid reads the score Attributor already
            # computed (and cached) while resolving agent_name for this pid
            # in _gather_spawn_info — see Attributor._score_behaviour.
            confidence = self.attributor.get_behaviour_score_for_pid(pid) if is_unidentified else None

            agent_id = await self.attributor.get_or_create_agent(agent_name, pid, confidence=confidence)
            session_id = await self.attributor.sessions.touch(agent_id)

            if not CORE_ONLY:
                await self.red_lines.check_dangerous_command(agent_id, agent_name, cmdline, exe_name, session_id=session_id)

                await self._check_config_exec(agent_id, agent_name, exe_path or cmdline, session_id)

            suspicious = _is_suspicious(cmdline, exe_name)
            # Behaviourally-flagged spawns are never "low" — being agent-like
            # enough to attribute at all is itself medium-worthy, same as an
            # explicitly suspicious command.
            severity = "medium" if (suspicious or is_unidentified) else "low"

            detail = {
                "pid": pid,
                "parent_pid": parent_pid,
                "command": exe_name,
                "args": info["args"],
                "suspicious": suspicious,
            }
            if is_unidentified:
                detail["behaviour_detected"] = True
                detail["confidence"] = confidence

            pending_rows.append({
                "pid": pid,
                "agent_id": agent_id,
                "session_id": session_id,
                "cmdline": cmdline,
                "exe_name": exe_name,
                "exe_path": exe_path,
                "detail": detail,
                "severity": severity,
                "suspicious": suspicious,
                "is_unidentified": is_unidentified,
                "confidence": confidence,
            })

        if not pending_rows:
            return

        # Batched insert instead of one INSERT (+ reading lastrowid) per PID
        # -- same pattern as Aggregator._write_batch. Up to len(pending_rows)
        # separate round trips through aiosqlite's single connection worker
        # thread was both slow on its own and, combined with Aggregator's own
        # writer contending for the same WAL-mode file, the main source of
        # this loop's multi-second-to-tens-of-seconds wall-clock cost.
        # executemany() doesn't hand back a lastrowid per row, so event_ids
        # are recovered below via one indexed SELECT keyed on
        # (event_type='proc_spawn', pid, id > id_before): ProcessWatcher is
        # the only writer of that event_type, and APScheduler runs at most
        # one poll() at a time (see poll()'s asyncio.timeout wrapper and the
        # "maximum number of running instances reached" skip), so no other
        # concurrent proc_spawn batch can land in that id range.
        async def _write_spawn_batch():
            # Runs on Aggregator's single writer task (see enqueue() below)
            # instead of directly on whatever task called poll() -- this is
            # the change from the earlier direct-get_db() version: the same
            # connection, but now serialized through the one queue every
            # other Aggregator-owned write already goes through, instead of
            # racing Aggregator's writer for the same WAL-mode connection.
            db = await get_db()
            id_before_cur = await db.execute("SELECT COALESCE(MAX(id), 0) AS m FROM events")
            id_before = (await id_before_cur.fetchone())["m"]

            await db.executemany(
                """
                INSERT INTO events
                    (agent_id, session_id, event_type, path, detail, severity, pid)
                VALUES (?, ?, 'proc_spawn', ?, ?, ?, ?)
                """,
                [
                    (
                        row["agent_id"], row["session_id"],
                        row["cmdline"] or row["exe_name"], json.dumps(row["detail"]),
                        row["severity"], row["pid"],
                    )
                    for row in pending_rows
                ],
            )
            await db.commit()

            event_id_cur = await db.execute(
                f"""
                SELECT id, pid FROM events
                WHERE event_type = 'proc_spawn' AND id > ? AND pid IN ({",".join("?" * len(pending_rows))})
                """,
                (id_before, *[row["pid"] for row in pending_rows]),
            )
            return {r["pid"]: r["id"] for r in await event_id_cur.fetchall()}

        if self.aggregator is not None:
            event_id_by_pid = await self.aggregator.enqueue(_write_spawn_batch)
        else:
            event_id_by_pid = await _write_spawn_batch()

        for row in pending_rows:
            event_id = event_id_by_pid.get(row["pid"])

            if row["suspicious"]:
                await self.alerter.fire_alert(
                    row["agent_id"],
                    "medium",
                    title="Suspicious command spawned",
                    description=f"Agent spawned process (pid={row['pid']}) with a suspicious command: {row['cmdline']}",
                    reason="suspicious_command",
                    event_id=event_id,
                    extra_detail={"pid": row["pid"], "cmdline": row["cmdline"]},
                    target=row["exe_path"],
                    session_id=row["session_id"],
                )

            if row["is_unidentified"]:
                confidence = row["confidence"]
                confidence_str = f"{confidence:.2f}" if confidence is not None else "unknown"
                await self.alerter.fire_alert(
                    row["agent_id"],
                    "medium",
                    title="Unidentified agent-like process detected",
                    description=(
                        f"Process {row['exe_name']} (pid={row['pid']}) doesn't match any known agent by name, "
                        f"but its recent behaviour scored {confidence_str} against V-LAW's "
                        f"agent-likeness signals: {row['cmdline'] or row['exe_name']}"
                    ),
                    reason="unidentified_agent_behaviour",
                    event_id=event_id,
                    extra_detail={
                        "pid": row["pid"], "process_name": row["exe_name"],
                        "confidence": confidence, "cmdline": row["cmdline"],
                    },
                    target=row["exe_path"],
                    session_id=row["session_id"],
                )

    async def _run_process_scan(self, agent_pids: list[int] | None = None) -> dict:
        """Spawns _process_scan_worker.py as a subprocess to do the full
        psutil.process_iter() pass, and — for `agent_pids` only, never
        "every process" — the worker also collects environ()/cmdline()/
        exe() there, so those GIL-holding calls happen in this disposable
        process too, not here. If it hangs, hard-kills it after
        _SCAN_TIMEOUT_SECONDS. Returns {"processes": [...], "envs": {pid:
        {...}}, "cmdlines": {pid: {"args", "exe_path"}}} — all empty on
        timeout or any failure, plus "failed": True on those two paths so
        callers (see _snapshot_pids) can tell a genuinely-failed scan apart
        from a scan that legitimately saw zero processes, and retain prior
        state instead of wiping it. Dict keys under "envs"/"cmdlines" come
        back from JSON as strings; converted to int here so callers can
        index by the same int PIDs used everywhere else in this file.

        The subprocess has its own GIL — a blocking psutil call there can
        never freeze this process's event loop, and unlike a
        run_in_executor thread (same process, same GIL), it can actually be
        killed out from under a stuck call via proc.kill()."""
        empty_result = {"processes": [], "envs": {}, "cmdlines": {}}
        failed_result = {**empty_result, "failed": True}
        # In a frozen (PyInstaller) build, sys.executable is this app's own
        # exe, not a python.exe, and _WORKER_PATH's .py file was never
        # bundled as a loose file for it to exec -- spawning
        # [sys.executable, _WORKER_PATH] there just relaunches a second
        # full copy of the app, which hits the single-instance lock and
        # exits, leaving this parent to fail parsing its startup-banner
        # text as JSON. Re-invoke the same exe with a sentinel argument
        # instead (see main.py, handled before the instance lock); dev
        # mode (unfrozen) keeps exec'ing the standalone worker script.
        if getattr(sys, "frozen", False):
            args = [sys.executable, "--process-scan-worker"]
        else:
            args = [sys.executable, _WORKER_PATH]
        if agent_pids:
            args.append(",".join(str(p) for p in agent_pids))

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_SCAN_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(
                    "ProcessScan subprocess timed out after %ds and was killed -- returning empty snapshot",
                    _SCAN_TIMEOUT_SECONDS,
                )
                return failed_result

            result = json.loads(stdout.decode("utf-8", errors="replace"))
            if result.get("error"):
                logger.warning("ProcessScan worker error: %s", result["error"])

            return {
                "processes": result.get("processes", []),
                "envs": {int(pid): env for pid, env in result.get("envs", {}).items()},
                "cmdlines": {int(pid): cl for pid, cl in result.get("cmdlines", {}).items()},
            }

        except Exception as e:
            logger.error("ProcessScan subprocess failed: %s", e)
            return failed_result

    async def _snapshot_pids(self) -> set[int]:
        """Builds self._pid_snapshot from _run_process_scan's subprocess
        result — _gather_spawn_info's Attributor.get_agent_for_pid calls
        then resolve entirely from that dict rather than each opening a
        fresh OS process handle per parent-chain level (see
        Attributor._walk_parent_chain_from_snapshot). Awaits directly on
        the event loop (no run_in_executor): all psutil I/O, including
        environ()/cmdline()/exe(), now happens in the scan subprocess, not
        in this process at all — there is nothing left here to offload.

        Two subprocess calls per cycle: the first gets the bare process
        list (cheap — no environ()/cmdline() for anyone yet, since which
        PIDs are agent-related isn't known until this list is in hand); the
        second requests environ()/cmdline()/exe() for a narrowed set of
        PIDs (see below), bounded by the same _SCAN_TIMEOUT_SECONDS, and
        can never block this process's event loop.

        cmdline/exe_path are cached in self._cmdline_snapshot permanently,
        per PID, once fetched — they can't change for a process's lifetime
        (same reasoning Attributor already applies to parent-chain caching),
        so re-requesting them from the scan subprocess every cycle for the
        same still-running PIDs was pure waste, and self._known_agent_pids
        only grows over a long-running session (a PID drops out only on
        exit — see _scan_all_agent_processes_for_env_redirect's stale_pids
        handling), so that waste compounded every cycle.

        env is deliberately NOT cached this way: RL7
        (check_env_var_redirect) must see a process's *current* environment
        every cycle to catch a redirect set at any point during that
        process's life, not just the first time it's observed — caching it
        would make RL7 blind to anything after the first scan. It's still
        re-fetched every cycle, just scoped down to agent-process-NAMED
        PIDs only (the ones _scan_all_agent_processes_for_env_redirect
        actually inspects), not the full self._known_agent_pids superset,
        which also includes non-agent-named children attributed via
        parent-chain (e.g. a curl.exe spawned by claude.exe) whose own env
        RL7 never looks at."""
        scan_result = await self._run_process_scan()
        if scan_result.get("failed"):
            logger.warning(
                "ProcessWatcher: scan failed this cycle (timeout or subprocess "
                "error) -- retaining previous pid_snapshot (%d PID(s)) instead "
                "of wiping it, so a transient failure doesn't force next "
                "cycle to treat every running process as new",
                len(self._pid_snapshot),
            )
            return set(self._pid_snapshot.keys())

        processes = scan_result["processes"]
        snapshot: dict[int, dict] = {}
        for p in processes:
            pid = p.get("pid")
            if pid:
                snapshot[pid] = {
                    "name": p.get("name", ""),
                    "ppid": p.get("ppid", 0),
                    "status": p.get("status", ""),
                }

        self._pid_snapshot = snapshot
        logger.info("ProcessWatcher snapshot: %d total OS PID(s)", len(snapshot))

        agent_candidate_pids = {
            pid for pid, info in snapshot.items()
            if _is_agent_process_name(info["name"])
        }
        agent_candidate_pids |= self._known_agent_pids

        cmdline_new_pids = agent_candidate_pids - set(self._cmdline_snapshot.keys())
        env_refresh_pids = {
            pid for pid in agent_candidate_pids
            if _is_agent_process_name(snapshot.get(pid, {}).get("name", ""))
        }
        fetch_pids = cmdline_new_pids | env_refresh_pids

        logger.info(
            "ProcessWatcher env-redirect scan: %d new PID(s) of %d known",
            len(cmdline_new_pids), len(agent_candidate_pids),
        )

        if fetch_pids:
            env_result = await self._run_process_scan(agent_pids=list(fetch_pids))
            fresh_envs = env_result["envs"]
            fresh_cmdlines = env_result["cmdlines"]

            self._env_snapshot = {pid: fresh_envs[pid] for pid in env_refresh_pids if pid in fresh_envs}
            for pid in cmdline_new_pids:
                if pid in fresh_cmdlines:
                    self._cmdline_snapshot[pid] = fresh_cmdlines[pid]
        else:
            self._env_snapshot = {}

        # Memory-growth safeguard: drop cached cmdline entries for PIDs that
        # have exited entirely (not just PIDs that dropped out of this
        # cycle's agent-candidate set), so the cache doesn't grow unbounded
        # over a long-running session.
        exited_pids = set(self._cmdline_snapshot.keys()) - set(snapshot.keys())
        for pid in exited_pids:
            del self._cmdline_snapshot[pid]

        return set(snapshot.keys())

    async def _gather_spawn_info(self, pids: set[int]) -> list[dict]:
        """Pure Python dict access — no psutil calls at all, so no
        run_in_executor/thread pool/to_thread needed for any of this; this
        process never touches psutil directly.

        Agent-name resolution goes through Attributor.get_named_agent_for_pid
        for every new PID — the same name-match parent-chain walk used
        elsewhere (still catches a non-agent-named child like
        curl/powershell/nc spawned under a known agent parent, so
        suspicious-command detection doesn't lose them), but it never falls
        through to Attributor._score_behaviour's synchronous SQLite
        connection. That means spawn-time "unidentified_agent" behavioural
        detection no longer fires from this loop — an agent-like process
        that doesn't match any known name won't be flagged at the moment it
        spawns; it can still be caught later, incidentally, if
        NetworkWatcher/McpWatcher/file_watcher happen to observe activity
        from that same PID, since those call get_agent_for_pid directly and
        independently of this method.

        Purely synchronous dict access when pid_snapshot is supplied (see
        Attributor._walk_parent_chain_from_snapshot), so it's called
        directly — no asyncio.to_thread, no Semaphore, no concurrency bound
        needed; get_named_agent_for_pid can't block.

        A PID not present in self._cmdline_snapshot (its name didn't match
        AGENT_PROCESS_NAMES and it wasn't already in self._known_agent_pids
        when this cycle's candidate set was computed) falls back to an empty
        cmdline/its bare exe_name — unchanged graceful degradation."""
        agent_name_by_pid: dict[int, str | None] = {
            pid: self.attributor.get_named_agent_for_pid(pid, pid_snapshot=self._pid_snapshot)
            for pid in pids
            if pid in self._pid_snapshot
        }

        infos = []
        for pid in pids:
            snap_info = self._pid_snapshot.get(pid)
            if snap_info is None:
                # Not in this cycle's snapshot (e.g. exited between
                # _snapshot_pids and now) — nothing to report for this PID;
                # there is no live-lookup fallback available since this
                # process no longer talks to psutil at all.
                continue

            exe_name = snap_info["name"]
            parent_pid = snap_info.get("ppid")

            agent_name = agent_name_by_pid.get(pid)
            if agent_name is not None:
                self._known_agent_pids.add(pid)

            cmdline_info = self._cmdline_snapshot.get(pid)
            if cmdline_info is not None:
                args = cmdline_info.get("args") or []
                exe_path = cmdline_info.get("exe_path") or exe_name
            else:
                args = []
                exe_path = exe_name
            cmdline = " ".join(args)

            infos.append({
                "pid": pid,
                "cmdline": cmdline,
                "args": args,
                "exe_name": exe_name,
                "exe_path": exe_path,
                "parent_pid": parent_pid,
                "agent_name": agent_name,
            })
        return infos

    def _scan_all_agent_processes_for_env_redirect(self) -> list[dict]:
        """RL7: re-inspects every PID _gather_spawn_info has already
        resolved to a known agent (self._known_agent_pids), not just PIDs
        newly spawned this poll and not just a single "first match" PID.
        Each matching process's own environment is checked on its own
        terms, so if 5 claude.exe processes are running and only one has
        ANTHROPIC_BASE_URL redirected, that exact PID is the one the alert
        is attributed to — see core.red_lines.RedLines.check_env_var_redirect's
        pid parameter.

        Pure Python dict access — no psutil calls at all. Reads process
        existence/name from self._pid_snapshot and env vars from
        self._env_snapshot, both populated by _snapshot_pids from the scan
        subprocess's result (self._known_agent_pids is included in the PID
        list _snapshot_pids requests environ() for — see
        _run_process_scan/_process_scan_worker.py), instead of calling
        proc.environ() here directly. That call previously ran in-process
        (even via a thread-pool executor) and could hold the GIL for the
        duration of the underlying OpenProcess/ReadProcessMemory syscall
        long enough to freeze the whole process, including the event loop
        thread that would otherwise fire poll()'s own asyncio.timeout — a
        subprocess call can't do that to this process, and can be killed
        out from under a stuck call, which a thread sharing this process's
        GIL cannot.

        No longer runs in the thread pool executor — there's nothing
        blocking left to offload. Returns the matches instead of calling
        async DB/red_lines code directly; poll() awaits on the results."""
        logger.info("ProcessWatcher env-redirect scan: %d known agent PID(s)", len(self._known_agent_pids))
        hits = []
        stale_pids = []
        for pid in self._known_agent_pids:
            snap_info = self._pid_snapshot.get(pid)
            if snap_info is None:
                stale_pids.append(pid)
                continue
            name = snap_info["name"]

            if not _is_agent_process_name(name):
                continue  # cheap name check first — never request environ() for a non-agent-host process

            agent_name = _match_known_agent_name(name)
            if agent_name is None:
                continue

            full_env = self._env_snapshot.get(pid)
            if full_env is None:
                # Not in this cycle's env_snapshot — either the worker
                # couldn't read it (AccessDenied/exited, see
                # _process_scan_worker.py) or this pid wasn't part of the
                # agent-candidate set _snapshot_pids requested environ()
                # for this cycle. Best-effort either way: skip, never block.
                continue

            agent_env = {k: v for k, v in full_env.items() if k.upper() in RELEVANT_ENV_VARS}
            if not agent_env:
                continue

            hits.append({"pid": pid, "agent_name": agent_name, "agent_env": agent_env})

        for pid in stale_pids:
            self._known_agent_pids.discard(pid)

        return hits

    async def _check_config_exec(self, agent_id: int, agent_name: str, spawned_path: str, session_id: str | None = None) -> None:
        """RL7b (CVE-2025-59536 pattern), spawn-triggered half: consumes a
        pending config write recorded by file_watcher.py (shared module-level
        state in core.red_lines) if this spawn falls within the correlation
        window. See file_watcher.py::_check_config_exec for the file-write
        half of the same rule."""
        pending = self.red_lines.pop_pending_config_write(agent_id)
        if pending is None:
            return

        db = await get_db()
        cur = await db.execute(
            "SELECT COUNT(*) c FROM sessions WHERE agent_id = ? AND ended_at IS NOT NULL",
            (agent_id,),
        )
        prior_approved_sessions = (await cur.fetchone())["c"]

        await self.red_lines.check_malicious_config_execution(
            agent_id, agent_name,
            config_path=pending["path"], config_write_ts=pending["ts"],
            triggered_event_path=spawned_path, triggered_event_ts=time.time(),
            prior_approved_sessions=prior_approved_sessions,
            session_id=session_id,
        )
