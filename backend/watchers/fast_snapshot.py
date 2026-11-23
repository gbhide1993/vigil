"""A cheap process list: pid, parent pid and name from one CreateToolhelp32Snapshot call (no OpenProcess, no psutil, no
subprocess, no administrator rights). About 13 ms of CPU for 380 processes. It sees a process that lives for about a
second or more; one that starts and exits between two snapshots is still missed. Windows only; elsewhere it returns {}.
"""

import ctypes
import sys
from ctypes import wintypes

TH32CS_SNAPPROCESS = 0x2
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG), ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


_kernel32 = None


def _api():
    global _kernel32
    if _kernel32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
        k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        _kernel32 = k
    return _kernel32


def snapshot() -> dict[int, dict]:
    """{pid: {"name": lower-case exe name, "ppid": parent pid}}; {} if the call fails or this is not Windows."""
    if sys.platform != "win32":
        return {}
    try:
        k = _api()
        handle = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not handle or handle == INVALID_HANDLE_VALUE:
            return {}
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            out: dict[int, dict] = {}
            ok = k.Process32FirstW(handle, ctypes.byref(entry))
            while ok:
                out[entry.th32ProcessID] = {"name": entry.szExeFile.lower(), "ppid": entry.th32ParentProcessID}
                ok = k.Process32NextW(handle, ctypes.byref(entry))
            return out
        finally:
            k.CloseHandle(handle)
    except Exception:
        return {}
