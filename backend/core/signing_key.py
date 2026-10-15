"""The per-install Ed25519 signing key (Stage 3 of docs/design/evidence-anchoring.md, section 5.1).

Created on first use, kept in the key directory (VLAW_KEY_DIR, core/evidence_anchor.key_dir()) beside the
anchor state:

  install.key       the private key. On Windows it is wrapped with DPAPI (user scope); elsewhere, or if DPAPI
                    fails, it is a plain file and the "protection" field says "none".
  install.pub.json  install_id, the public key (base64, 32 bytes) and its fingerprint (SHA-256 of those 32
                    bytes, hex). This is the only part that ever goes into an evidence bundle.

What the key does NOT give (section 5.2): Vigil, and the agent it monitors, run as the same Windows user, so
any process of that user can read the key and sign with it. A signature made with it proves that the bundle
was not edited after export by anyone WITHOUT the key. It does not prove who exported the bundle, and it
does not prove the data in it is true or complete.
"""

import base64
import hashlib
import json
import logging
import os
import sys
import tempfile
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("vlaw")

PRIVATE_FILE = "install.key"
PUBLIC_FILE = "install.pub.json"


def fingerprint_of(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()


# ------------------------------------------------------------------ DPAPI (Windows, user scope)

def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buffer = ctypes.create_string_buffer(data, len(data))
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    out = Blob()
    function = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = function(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _wrap(seed: bytes) -> tuple[str, bytes]:
    if sys.platform == "win32":
        try:
            return "dpapi", _dpapi(seed, True)
        except Exception:
            logger.warning("signing key: DPAPI is unavailable, the key is stored without OS protection")
    return "none", seed


def _unwrap(protection: str, blob: bytes) -> bytes:
    return _dpapi(blob, False) if protection == "dpapi" else blob


# ------------------------------------------------------------------ files

def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".key-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_public(directory: Path) -> dict | None:
    try:
        data = json.loads((directory / PUBLIC_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("public_key") or not data.get("fingerprint"):
        return None
    return data


def ensure_key(directory: Path, install_id: str | None = None) -> dict:
    """Returns the public record {install_id, public_key, fingerprint, protection}, creating the key pair on
    first use. install_id is the one the anchor series already uses (so the two never disagree); it is only
    written when the key is created. Raises OSError if the key directory cannot be written."""
    existing = load_public(directory)
    if existing and (directory / PRIVATE_FILE).exists():
        return existing
    private = ed25519.Ed25519PrivateKey.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    protection, blob = _wrap(seed)
    _write_atomic(directory / PRIVATE_FILE, json.dumps({"v": 1, "protection": protection, "key": base64.b64encode(blob).decode()}))
    record = {
        "v": 1, "install_id": install_id or str(uuid.uuid4()),
        "public_key": base64.b64encode(public).decode(), "fingerprint": fingerprint_of(public), "protection": protection,
    }
    _write_atomic(directory / PUBLIC_FILE, json.dumps(record, indent=2, sort_keys=True))
    return record


def load_private(directory: Path) -> ed25519.Ed25519PrivateKey:
    data = json.loads((directory / PRIVATE_FILE).read_text(encoding="utf-8"))
    seed = _unwrap(data.get("protection", "none"), base64.b64decode(data["key"]))
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def sign(directory: Path, message: bytes) -> bytes:
    return load_private(directory).sign(message)


def public_fingerprint(directory: Path) -> str | None:
    """The fingerprint to put in a new anchor, creating nothing: None when there is no key yet."""
    record = load_public(directory)
    return record["fingerprint"] if record else None
