"""Plain-English session digests. Pure string templating over stats the
session already has rolled up (core/sessions.py::_roll_up_session_stats)
— no LLM, no extra queries. One sentence per notable dimension, joined
into a short paragraph; a totally quiet session gets a single clean line
rather than a wall of zeros.
"""


import re

_LEGACY_ZERO_READS =re.compile(r"\bread 0 and wrote (\d+) (files?)\b")


def display_summary(summary):
    """Display-time rewrite of summaries stored before reads were described honestly:
    "read 0 and wrote N files" -> "wrote N files (file reads are not recorded)". Only a read count of 0 is
    rewritten (a nonzero count is a real number and stays). The stored row is never changed."""
    if not summary:
        return summary
    return _LEGACY_ZERO_READS.sub(r"wrote \1 \2 (file reads are not recorded)", summary)


def generate_summary(agent_name: str, session: dict) -> str:
    """session: a sessions row (dict) already rolled up — file_reads,
    file_writes, net_egress_bytes, proc_spawns, cred_accesses,
    mcp_connects, alert_count, anomaly_score all present."""
    parts: list[str] = []

    file_reads = session.get("file_reads") or 0
    file_writes = session.get("file_writes") or 0
    # File reads are not recorded on Windows, so file_reads is 0 there. Say what was recorded and that
    # reads are not recorded, instead of printing "read 0".
    def files(n: int) -> str:
        return f"{n} file{'s' if n != 1 else ''}"

    if file_reads:
        parts.append(f"read {files(file_reads)}" + (f" and wrote {files(file_writes)}" if file_writes else ""))
    elif file_writes:
        parts.append(f"wrote {files(file_writes)} (file reads are not recorded)")

    net_mb = (session.get("net_egress_bytes") or 0) / (1024 * 1024)
    if net_mb >= 0.01:
        parts.append(f"sent {net_mb:.2f} MB over the network")

    proc_spawns = session.get("proc_spawns") or 0
    if proc_spawns:
        parts.append(f"spawned {proc_spawns} process{'es' if proc_spawns != 1 else ''}")

    cred_accesses = session.get("cred_accesses") or 0
    if cred_accesses:
        parts.append(f"touched credential paths {cred_accesses} time{'s' if cred_accesses != 1 else ''}")

    if not parts:
        return f"{agent_name} had a quiet session with no notable file or process activity."

    body = "; ".join(parts)
    sentence = f"{agent_name} {body} this session."

    alert_count = session.get("alert_count") or 0
    anomaly_score = session.get("anomaly_score") or 0

    if alert_count:
        sentence += f" {alert_count} alert{'s' if alert_count != 1 else ''} were raised."
    if anomaly_score > 0.7:
        sentence += f" This session scored {anomaly_score:.2f} against {agent_name}'s baseline — unusually high."

    return sentence
