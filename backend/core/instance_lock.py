"""Single-instance lock for the backend.

The lock file lives in the app data dir (the one holding vlaw.db), not
next to the code: under PyInstaller onefile "next to the code" is the
temporary _MEI directory, which is different for every launch, so two
backends never saw each other's lock.

The lock is an OS-level byte-range lock (msvcrt on Windows, flock
elsewhere), so the OS drops it when the holder exits or crashes and a
stale lock file can never block a restart. The PID written into the file
is informational only (used in the "already running" message); a leftover
file naming a dead PID, or an unreadable or garbage file, is simply taken
over."""

import logging
import os

logger = logging.getLogger("vlaw")

LOCK_FILENAME = "vigil.lock"
# The locked byte sits well past the PID text so other processes can still
# read the PID (a Windows byte-range lock also blocks reads of that range).
_LOCK_OFFSET = 4096


class InstanceAlreadyRunning(Exception):
    def __init__(self, pid: int | None):
        self.pid = pid
        super().__init__(f"another Vigil backend is already running (pid={pid})")


def _try_lock(f) -> bool:
    f.seek(_LOCK_OFFSET)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    finally:
        f.seek(0)
    return True


def _read_pid(path: str) -> int | None:
    try:
        # buffering=0: a buffered read asks the OS for a whole block, which
        # on Windows crosses the locked byte and fails with PermissionError.
        with open(path, "rb", buffering=0) as f:
            return int(f.read(32).decode("ascii", "ignore").strip())
    except (OSError, ValueError):
        return None


def acquire_instance_lock(data_dir: str):
    """Takes the lock and returns the open file handle, which the caller
    must keep referenced for the life of the process (closing it, or the
    process exiting, releases the lock). Raises InstanceAlreadyRunning if
    a live process holds it.

    If the lock file itself cannot be created or opened (read-only dir,
    permissions), logs a warning and returns None rather than refusing to
    start: the data dir is also where vlaw.db lives, so a genuinely
    unusable dir fails later with a clearer database error, and refusing
    here would turn a locking glitch into a backend that never starts."""
    path = os.path.abspath(os.path.join(str(data_dir), LOCK_FILENAME))
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # "a+b": never truncates, so a failed attempt cannot wipe the
        # running instance's PID text.
        f = open(path, "a+b")
    except OSError as e:
        logger.warning("instance lock file %s unusable (%s); continuing without a lock", path, e)
        return None

    if not _try_lock(f):
        f.close()
        raise InstanceAlreadyRunning(_read_pid(path))

    try:
        f.seek(0)
        f.truncate(0)
        f.write(str(os.getpid()).encode("ascii"))
        f.flush()
    except OSError as e:
        logger.warning("could not write pid to instance lock %s (%s); lock is still held", path, e)
    return f


def release_instance_lock(f) -> None:
    """Closes the handle (which releases the OS lock). The file is left in
    place on purpose: deleting it would race with another process that
    has just opened it to take the lock."""
    if f is None:
        return
    try:
        f.close()
    except OSError:
        pass
