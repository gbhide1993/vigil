"""Layer 2a embedded priors: researched starting distributions of what
normal looks like for each known agent. Unlike Layer 1's baseline (which
learns from this machine's own history over 14 days), these apply from
session 1 — there is no cold-start gap.
"""

AGENT_PRIORS = {
    "claude_code": {
        "file_events_per_session":    {"typical": 45,  "high": 150, "critical": 400},
        "network_events_per_session": {"typical": 8,   "high": 30,  "critical": 80},
        "process_spawns_per_session": {"typical": 12,  "high": 40,  "critical": 100},
        "read_write_ratio":           {"typical": 3.0, "high": 10.0, "critical": 25.0},
        "normal_hours":               [6, 22],
        "known_network_destinations": [
            "api.anthropic.com", "statsig.anthropic.com",
            "sentry.io", "localhost", "127.0.0.1",
            "update.googleapis.com", "clients2.google.com",
            "github.com", "raw.githubusercontent.com",
            "registry.npmjs.org", "pypi.org",
        ],
    },
    "cursor": {
        "file_events_per_session":    {"typical": 60,  "high": 200, "critical": 500},
        "network_events_per_session": {"typical": 12,  "high": 45,  "critical": 100},
        "process_spawns_per_session": {"typical": 8,   "high": 30,  "critical": 80},
        "read_write_ratio":           {"typical": 2.5, "high": 8.0,  "critical": 20.0},
        "normal_hours":               [6, 22],
        "known_network_destinations": [
            "api2.cursor.sh", "marketplace.cursorapi.com",
            "api.openai.com", "sentry.io", "localhost", "127.0.0.1",
            "update.googleapis.com", "github.com",
            "registry.npmjs.org", "pypi.org", "extensions.vscode.dev",
        ],
    },
    "copilot": {
        "file_events_per_session":    {"typical": 30,  "high": 100, "critical": 300},
        "network_events_per_session": {"typical": 15,  "high": 50,  "critical": 120},
        "process_spawns_per_session": {"typical": 5,   "high": 20,  "critical": 60},
        "read_write_ratio":           {"typical": 4.0, "high": 12.0, "critical": 30.0},
        "normal_hours":               [6, 22],
        "known_network_destinations": [
            "copilot-proxy.githubusercontent.com",
            "api.githubcopilot.com", "githubcopilot.com",
            "vscode.blob.core.windows.net", "localhost", "127.0.0.1",
            "github.com", "api.github.com", "update.googleapis.com",
        ],
    },
    "_default": {
        "file_events_per_session":    {"typical": 50,  "high": 180, "critical": 450},
        "network_events_per_session": {"typical": 10,  "high": 40,  "critical": 100},
        "process_spawns_per_session": {"typical": 10,  "high": 35,  "critical": 90},
        "read_write_ratio":           {"typical": 3.0, "high": 10.0, "critical": 25.0},
        "normal_hours":               [6, 22],
        "known_network_destinations": ["localhost"],
    },
}


def get_prior(agent_name: str) -> dict:
    name = (agent_name or "").lower()
    for key in AGENT_PRIORS:
        if key != "_default" and key in name:
            return AGENT_PRIORS[key]
    return AGENT_PRIORS["_default"]
