"""Single on/off switch for every feature outside Vigil's frozen core.

Frozen core (never gated by this flag): OS-level file/process/network
capture (watchers/file_watcher.py, etw_file_watcher.py, process_watcher.py,
network_watcher.py's capture path), multi-tier confidence-gated attribution
(core/attributor.py), cross-agent + burst/network/process correlation
(core/cross_agent.py, core/correlation_engine.py), and session verification
-- agent-reported vs. OS-observed (core/verification.py). Also never gated:
api/mcp_routes.py + core/mcp_service.py, the read-only MCP server the
VS Code extension calls directly in production -- disabling it breaks an
existing client, independent of whether it's "core" by product scope.

Everything else -- the judgment/scoring layer (core/red_lines.py's Red
Line rules, core/layer2a.py, core/layer2b.py, and the core/alerter.py
alerts they fire) and adjacent-but-not-evidence features
(core/config_auditor.py, core/cve_check.py, api/digest_api.py) -- is gated
by CORE_ONLY below.

Defaults to False: full current behavior, nothing silently disabled on a
normal deploy. Set VLAW_CORE_ONLY=1 to cut the entire non-core surface
instantly -- no code edit, no redeploy -- e.g. when one of these subsystems
is suspected of causing an incident and needs to be gone right now.
"""

import os

CORE_ONLY = os.environ.get("VLAW_CORE_ONLY", "0").strip().lower() in ("1", "true", "yes")
