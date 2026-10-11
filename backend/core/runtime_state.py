"""State shared between main.py and the API routes while the backend runs.

Why this module exists: in the PyInstaller exe (and with `python main.py`)
main.py runs as `__main__`. A route that did `import main` therefore loaded a
SECOND copy of main.py under the name "main": a second logging setup (every
log line printed twice), a second FastAPI app, and, worst, a second, empty
`_state`, so scope add/remove never reached the real file observer. Nothing
outside main.py may import main; anything routes need from the running
backend lives here, and main.py aliases these same objects
(`_state`, `_stats_cache`).
"""

# Handles set by main.py's startup: "observer", "file_handler", "scheduler",
# "aggregator", "baseline", "license_status".
state: dict = {}

# /api/stats cache (see main.py get_stats); routes that change alert state
# clear it by setting stats_cache["data"] = None.
stats_cache: dict = {"data": None, "computed_at": 0.0}
