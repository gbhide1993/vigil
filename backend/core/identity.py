"""Captures which OS user account and machine a session ran under --
the human-identity half of 'who touched this,' complementing
core/attributor.py's agent-identity half. Read once per session at
creation (core/sessions.py's touch()), not cached globally, so a
session captured under one Windows user stays correctly attributed to
that user even if the OS account active on the machine changes later."""

import getpass
import socket


def get_operator_identity() -> tuple[str | None, str | None]:
    """Returns (username, hostname). getpass.getuser() is used over
    os.getlogin() because getlogin() raises in several real contexts
    this backend can run in (no controlling tty, run as a Windows
    service) -- getpass.getuser() falls back through LOGNAME/USER/
    USERNAME env vars first and is far more reliable here. Never
    raises: both failure modes return None for that field rather than
    taking the caller down."""
    try:
        username = getpass.getuser()
    except Exception:
        username = None
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = None
    return username, hostname
