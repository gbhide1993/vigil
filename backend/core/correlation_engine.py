LLM_API_DOMAINS = {
    "api.anthropic.com", "api.openai.com", "openai.azure.com",
    "generativelanguage.googleapis.com", "api.cohere.ai", "api.mistral.ai",
}

KNOWN_AGENT_BINARIES = {
    "claude", "claude-code", "cursor", "windsurf", "copilot",
    "cody", "continue", "aider", "devin",
}


def _strip_exe_suffix(name: str) -> str:
    # str.rstrip(".exe") strips trailing characters in the set {.,e,x}, not
    # the literal suffix -- e.g. "code".rstrip(".exe") wrongly returns "cod".
    return name[:-4] if name.endswith(".exe") else name


class CorrelationEngine:
    def compute_confidence(
        self,
        burst: dict,
        network_events: list[dict],      # [{domain, timestamp, pid}]
        process_snapshot: dict[int, dict], # {pid: {name, ppid, env}}
    ) -> dict:
        layers = []     # independent observation layers
        signals = []    # all signal descriptions (for attribution_basis)
        who_candidate = None

        t0, t1 = burst["start_time"], burst["end_time"]

        # LAYER 1 — Network (kernel-level, independent of process self-report)
        llm_calls = [
            e for e in network_events
            if t0 - 30 <= e.get("timestamp", 0) <= t1 + 30
            and any(d in e.get("domain", "") for d in LLM_API_DOMAINS)
        ]
        if llm_calls:
            layers.append("network")
            domains_seen = {e["domain"] for e in llm_calls}
            signals.append(f"LLM API calls: {domains_seen}")
            for e in llm_calls:
                pid = e.get("pid")
                if pid and pid in process_snapshot:
                    name = _strip_exe_suffix(process_snapshot[pid].get("name", "").lower())
                    if name in KNOWN_AGENT_BINARIES:
                        who_candidate = name
                        signals.append(f"network PID {pid} → known agent: {name}")

        # LAYER 2 — Process tree (OS process table, independent of network)
        agent_pids = {
            pid for pid, info in process_snapshot.items()
            if _strip_exe_suffix(info.get("name", "").lower()) in KNOWN_AGENT_BINARIES
        }
        if agent_pids and "network" in layers:
            # Two independent layers agree: process tree corroborates network
            layers.append("process_tree")
            for pid in agent_pids:
                name = _strip_exe_suffix(process_snapshot[pid].get("name", "").lower())
                signals.append(f"known agent binary in process table: {name} (PID {pid})")
                if not who_candidate:
                    who_candidate = name
        elif agent_pids:
            # Process name alone = single source, supporting only
            for pid in agent_pids:
                name = _strip_exe_suffix(process_snapshot[pid].get("name", "").lower())
                signals.append(f"known agent binary in process table (no network corroboration): {name}")

        # Env vars / self-report: supporting signals only, never elevate confidence
        for pid, info in process_snapshot.items():
            env = info.get("env", {})
            if any(k in env for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")):
                signals.append(f"LLM API key in env of PID {pid} (supporting only)")

        # CONFIDENCE DECISION — independence-gated
        n = len(layers)
        if n >= 2:
            confidence = "HIGH"
        elif n == 1:
            confidence = "MEDIUM"
        elif signals:
            confidence = "LOW"
            who_candidate = "Unknown AI agent"
        else:
            confidence = "UNKNOWN"
            who_candidate = None

        return {
            "who": who_candidate,
            "who_confidence": confidence,
            "attribution_basis": signals,
            "observation_layers": layers,
        }
