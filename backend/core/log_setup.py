"""Backend logging setup: size-rotated log file plus stdout, with chatty
third-party loggers held at WARNING.

Kept out of main.py so it can be tested without importing the whole app
(main.py runs path/env setup and starts importing every watcher at import
time)."""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# APScheduler logs "Running job ... / executed successfully" at INFO for
# every run, so the 30s process_watcher job alone wrote a line or two per
# cycle. watchdog logs per-observer event chatter at DEBUG/INFO.
QUIET_LOGGERS = ("apscheduler", "watchdog")


def configure_logging(log_path: str, level: str | int | None = None) -> logging.Logger:
    """Installs the root handlers (rotating file + stdout) and returns the
    "vlaw" logger. level defaults to $VLAW_LOG_LEVEL, then INFO."""
    if level is None:
        level = os.environ.get("VLAW_LOG_LEVEL", "INFO")
    # Handlers are attached directly rather than via logging.basicConfig,
    # which silently does nothing if the root logger already has a handler.
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    for handler in (
        RotatingFileHandler(
            log_path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
        ),
        logging.StreamHandler(sys.stdout),
    ):
        handler.setFormatter(formatter)
        root.addHandler(handler)
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)
    return logging.getLogger("vlaw")
