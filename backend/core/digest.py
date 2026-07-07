"""Plain-English session digests. Pure string templating over stats the
session already has rolled up (core/sessions.py::_roll_up_session_stats)
— no LLM, no extra queries. One sentence per notable dimension, joined
into a short paragraph; a totally quiet session gets a single clean line
rather than a wall of zeros.
"""


def generate_summary(agent_name: str, session: dict) -> str:
    """session: a sessions row (dict) already rolled up — file_reads,
    file_writes, net_egress_bytes, proc_spawns, cred_accesses,
    mcp_connects, alert_count, anomaly_score all present."""
    parts: list[str] = []

    file_reads = session.get("file_reads") or 0
    file_writes = session.get("file_writes") or 0
    if file_reads or file_writes:
        parts.append(f"read {file_reads} and wrote {file_writes} files")

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
        return f"{agent_name} had a quiet session with no notable file, network, or process activity."

    body = "; ".join(parts)
    sentence = f"{agent_name} {body} this session."

    alert_count = session.get("alert_count") or 0
    anomaly_score = session.get("anomaly_score") or 0

    if alert_count:
        sentence += f" {alert_count} alert{'s' if alert_count != 1 else ''} were raised."
    if anomaly_score > 0.7:
        sentence += f" This session scored {anomaly_score:.2f} against {agent_name}'s baseline — unusually high."

    return sentence
