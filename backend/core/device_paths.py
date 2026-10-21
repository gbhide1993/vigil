"""ETW reports file names as NT device paths ("\\Device\\HarddiskVolume3\\Users\\me\\a.txt"). Everything else in
Vigil (scope checks, the policy, the reports) uses drive-letter paths ("C:\\Users\\me\\a.txt"), so ETW paths are
converted before they are compared with anything or stored.

The drive-letter map comes from QueryDosDevice. It is built on first use and rebuilt, at most every 30 seconds, when a
device name is not in it (a volume mounted after start-up). A path that still cannot be converted is returned
unchanged: it is never guessed at.
"""

import ctypes
import os
import threading
import time

_REBUILD_INTERVAL_SECONDS = 30.0

_lock = threading.Lock()
_map: dict[str, str] = {}
_built_at = 0.0


def _query_dos_devices() -> dict[str, str]:
    """{"\\\\device\\\\harddiskvolume3": "C:", ...} for every drive letter that has a device."""
    mapping: dict[str, str] = {}
    if os.name != "nt":
        return mapping
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if kernel32.QueryDosDeviceW(f"{letter}:", buffer, len(buffer)):
            mapping[buffer.value.lower()] = f"{letter}:"
    return mapping


def _refresh(force: bool = False) -> None:
    global _map, _built_at
    with _lock:
        now = time.monotonic()
        if not force and _built_at and now - _built_at < _REBUILD_INTERVAL_SECONDS:
            return
        _map = _query_dos_devices()
        _built_at = now


def normalise_device_path(path: str | None, mapping: dict[str, str] | None = None) -> str | None:
    """A drive-letter (or UNC) path for an NT device path; any other path is returned as it was.

    `mapping` is for tests ({lower-case device: "C:"}); the running backend uses the real map."""
    if not path or path[0] != "\\":
        return path
    low = path.lower()

    # "\??\C:\x" and "\\?\C:\x" are already drive-letter paths with a prefix; "\??\UNC\srv\share" is a UNC path.
    for prefix in ("\\??\\", "\\\\?\\"):
        if low.startswith(prefix):
            rest = path[len(prefix):]
            if rest.lower().startswith("unc\\"):
                return "\\\\" + rest[4:]
            return rest

    if not low.startswith("\\device\\"):
        return path
    if low.startswith("\\device\\mup\\"):
        return "\\\\" + path[len("\\device\\mup\\"):]

    def convert(devices: dict[str, str]) -> str | None:
        for device, drive in devices.items():
            if low == device or low.startswith(device + "\\"):
                return drive + path[len(device):]
        return None

    if mapping is not None:
        return convert(mapping) or path
    _refresh()
    converted = convert(_map)
    if converted is None:
        _refresh()          # a volume mounted since the map was built (rate limited)
        converted = convert(_map)
    return converted or path
