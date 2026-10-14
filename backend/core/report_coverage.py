"""The "What this report covers" block printed near the top of the daily PDF, the per-session PDF and
the JSON export. One list, so the three outputs cannot word the same facts differently (a test checks
this). It states what Vigil records and what it does not, in the same plain words every time.

The last line follows from how the file watcher works (docs/COVERAGE.md): no file-read events are
produced on Windows by any tier, so the Red Lines that need a read (a .env read outside the project, a
cross-project read) cannot fire in any install, elevated or not. Changes to files under .ssh and
other credential-looking paths are detected, reads of them are not.
"""

TITLE = "What this report covers"

LINES = [
    "File writes and deletes and process spawns are recorded.",
    "File reads are not recorded.",
    "Network and MCP calls are not monitored in this version.",
    "Attribution to an agent is a best guess without the ETW tier.",
    "Generated folders (node_modules, .venv, dist, build) are ignored.",
    "Records stay on this machine.",
    "A change to a credential file is flagged, but reading one is not detected, so the Red Lines that "
    "depend on a read (a .env file read outside the project, a cross-project read) cannot fire.",
    "Alerts, sessions, audit entries and monitoring-gap records are stored but not integrity-protected in "
    "this version; only the event chain is.",
    "External timestamps are off unless you turn them on. When on, only a 32-byte hash of an anchor is sent to the "
    "timestamp service you choose (a second outbound connection), and a token covers only what existed when that "
    "anchor was made.",
]


def as_dict() -> dict:
    return {"title": TITLE, "lines": list(LINES)}
