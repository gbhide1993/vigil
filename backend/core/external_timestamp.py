"""Opt-in RFC 3161 external timestamps for evidence anchors: Stage 2 of docs/design/evidence-anchoring.md.

Off by default. Nothing is sent until the user turns it on AND gives a timestamp service URL. When on,
the only thing that leaves the machine is the 32-byte anchor hash inside a TimeStampReq (a fixed 59-byte
DER structure: version, the SHA-256 message imprint, certReq true; no policy, no nonce, no extensions).
No event, path, name or alert text is sent. This is a second outbound connection, after the digest webhook.

What a token proves, and what it does not: the service signed "this hash existed at time T". It covers
only what was in the anchor at that time (the chain head, the count, the table digest). It says nothing
about events recorded after that anchor, and nothing about whether the records were true or complete.

Verification is done here with `cryptography` and a small DER reader (no new dependency; the design doc
section 9.3 allows a small DER walk in the backend). The signature is checked only against a certificate
or chain the user supplies (external_timestamp_ca_pem). Without one, a token is reported as
"timestamp_unverified_signature": the imprint and time are read, the signature is not checked, and
nothing here ever calls that verified.

A failure, a timeout or an offline machine never blocks monitoring, sealing, anchoring or export: the
queue runs in its own scheduled job, and a failure only moves the anchor's next_try_at forward.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone

import aiosqlite
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

logger = logging.getLogger("vlaw")

DISCLOSURE = (
    "When on, Vigil sends only a 32-byte hash of an anchor to the timestamp service you choose. "
    "No events, file paths or names leave this machine. This is a second outbound connection."
)

CONFIG_ENABLED = "external_timestamp_enabled"
CONFIG_URL = "external_timestamp_url"
CONFIG_FALLBACK_URL = "external_timestamp_fallback_url"
CONFIG_CA_PEM = "external_timestamp_ca_pem"
CONFIG_SINCE_SEQ = "external_timestamp_since_seq"

# Backoff after a failed attempt (design doc 4.2): 1 min, 5 min, 30 min, then hourly.
BACKOFF_SECONDS = (60, 300, 1800, 3600)
MAX_PER_RUN = 5
REQUEST_TIMEOUT_SECONDS = 10.0

SIGNATURE_VERIFIED = "verified"
SIGNATURE_UNVERIFIED = "timestamp_unverified_signature"
SIGNATURE_FAILED = "failed"

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_HASHES = {OID_SHA256: hashes.SHA256, OID_SHA384: hashes.SHA384, OID_SHA512: hashes.SHA512}


class TimestampError(Exception):
    """A reply or token that is malformed, rejected, or does not match the hash that was sent."""


# ------------------------------------------------------------------ minimal DER

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _oid_bytes(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def _oid_text(content: bytes) -> str:
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _read(buf: bytes, pos: int = 0):
    """One TLV at pos: (tag, content_start, content_end). Raises TimestampError on anything malformed."""
    try:
        tag = buf[pos]
        length = buf[pos + 1]
        start = pos + 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                raise TimestampError("unsupported DER length")
            length = int.from_bytes(buf[start:start + count], "big")
            start += count
        end = start + length
        if end > len(buf):
            raise TimestampError("DER element runs past the end of the data")
        return tag, start, end
    except IndexError:
        raise TimestampError("truncated DER") from None


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, s, e = _read(buf, pos)
        out.append((tag, s, e))
        pos = e
    return out


def _child_with_header(buf: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """Like _children, but also gives each element's header start: (tag, header_start, content_start, content_end)."""
    out = []
    pos = start
    while pos < end:
        tag, s, e = _read(buf, pos)
        out.append((tag, pos, s, e))
        pos = e
    return out


# ------------------------------------------------------------------ the request

def build_request(anchor_hash_hex: str) -> bytes:
    """The RFC 3161 TimeStampReq for one anchor hash. Exactly: version 1, messageImprint (SHA-256 and the 32
    hash bytes), certReq TRUE. No reqPolicy, no nonce, no extensions: nothing but the digest."""
    digest = bytes.fromhex(anchor_hash_hex)
    if len(digest) != 32:
        raise ValueError("an anchor hash is 32 bytes")
    algorithm = der(0x30, der(0x06, _oid_bytes(OID_SHA256)) + der(0x05, b""))
    imprint = der(0x30, algorithm + der(0x04, digest))
    return der(0x30, der(0x02, b"\x01") + imprint + der(0x01, b"\xff"))


# ------------------------------------------------------------------ the reply

def _parse_gen_time(text: str) -> datetime:
    text = text.strip()
    if not text.endswith("Z"):
        raise TimestampError("genTime is not UTC")
    body = text[:-1]
    fraction = 0
    if "." in body:
        body, frac = body.split(".", 1)
        fraction = int((frac + "000000")[:6])
    return datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc, microsecond=fraction)


def parse_response(data: bytes) -> dict:
    """Reads a TimeStampResp (or a bare token). Returns {"granted", "status", "token"} with the token as DER
    bytes (the ContentInfo). Raises TimestampError for anything malformed or not granted."""
    top = _read(data, 0)
    if top[0] != 0x30:
        raise TimestampError("reply is not a DER SEQUENCE")
    parts = _child_with_header(data, top[1], top[2])
    if not parts:
        raise TimestampError("empty reply")
    # A bare token starts with the contentType OID; a TimeStampResp starts with PKIStatusInfo (a SEQUENCE).
    if parts[0][0] == 0x06:
        return {"granted": True, "status": 0, "token": data[:top[2]]}
    if parts[0][0] != 0x30:
        raise TimestampError("reply has no status")
    status_kids = _children(data, parts[0][2], parts[0][3])
    if not status_kids or status_kids[0][0] != 0x02:
        raise TimestampError("reply has no status integer")
    status = int.from_bytes(data[status_kids[0][1]:status_kids[0][2]], "big")
    if status not in (0, 1):
        raise TimestampError(f"the timestamp service refused the request (status {status})")
    if len(parts) < 2 or parts[1][0] != 0x30:
        raise TimestampError("the reply is granted but carries no token")
    return {"granted": True, "status": status, "token": data[parts[1][1]:parts[1][3]]}


def _signed_data(token: bytes):
    """(buf, signed_data_tlv) of a ContentInfo holding SignedData."""
    outer = _read(token, 0)
    if outer[0] != 0x30:
        raise TimestampError("token is not a ContentInfo")
    kids = _child_with_header(token, outer[1], outer[2])
    if len(kids) < 2 or kids[0][0] != 0x06 or _oid_text(token[kids[0][2]:kids[0][3]]) != OID_SIGNED_DATA:
        raise TimestampError("token is not CMS SignedData")
    wrapper = kids[1]
    if wrapper[0] != 0xA0:
        raise TimestampError("token has no content")
    inner = _read(token, wrapper[2])
    if inner[0] != 0x30:
        raise TimestampError("token SignedData is malformed")
    return token, inner


def read_token(token: bytes) -> dict:
    """Parses a token: {"imprint_algorithm", "imprint" (bytes), "gen_time" (datetime), "tst_info" (the signed
    bytes), "certificates", "signer_infos"}. Does not check any signature."""
    buf, sd = _signed_data(token)
    kids = _child_with_header(buf, sd[1], sd[2])
    # version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    if len(kids) < 4:
        raise TimestampError("SignedData is incomplete")
    encap = kids[2]
    if encap[0] != 0x30:
        raise TimestampError("no encapsulated content")
    encap_kids = _child_with_header(buf, encap[2], encap[3])
    if len(encap_kids) < 2 or encap_kids[1][0] != 0xA0:
        raise TimestampError("token carries no TSTInfo")
    octets = _read(buf, encap_kids[1][2])
    if octets[0] != 0x04:
        raise TimestampError("TSTInfo is not an OCTET STRING")
    tst_bytes = buf[octets[1]:octets[2]]

    tst = _read(tst_bytes, 0)
    tst_kids = _children(tst_bytes, tst[1], tst[2])
    if len(tst_kids) < 5 or tst_kids[2][0] != 0x30 or tst_kids[4][0] != 0x18:
        raise TimestampError("TSTInfo is malformed")
    imprint_kids = _children(tst_bytes, tst_kids[2][1], tst_kids[2][2])
    algorithm_kids = _children(tst_bytes, imprint_kids[0][1], imprint_kids[0][2])
    algorithm = _oid_text(tst_bytes[algorithm_kids[0][1]:algorithm_kids[0][2]])
    imprint = tst_bytes[imprint_kids[1][1]:imprint_kids[1][2]]
    gen_time = _parse_gen_time(tst_bytes[tst_kids[4][1]:tst_kids[4][2]].decode("ascii", "replace"))

    certificates = []
    signer_infos = None
    for tag, header, start, end in kids[3:]:
        if tag == 0xA0:
            for _t, h, _s, e in _child_with_header(buf, start, end):
                certificates.append(buf[h:e])
        elif tag == 0x31:
            signer_infos = (start, end)
    if signer_infos is None:
        raise TimestampError("token has no signer")
    return {
        "imprint_algorithm": algorithm, "imprint": imprint, "gen_time": gen_time, "tst_info": tst_bytes,
        "certificates": certificates, "buf": buf, "signer_infos": signer_infos,
    }


def check_imprint(token: bytes, anchor_hash_hex: str) -> datetime:
    """Confirms the token's messageImprint is exactly this anchor hash (SHA-256) and returns genTime.
    Raises TimestampError otherwise."""
    info = read_token(token)
    if info["imprint_algorithm"] != OID_SHA256 or info["imprint"] != bytes.fromhex(anchor_hash_hex):
        raise TimestampError("the token's message imprint is not this anchor's hash")
    return info["gen_time"]


# ------------------------------------------------------------------ signature

def load_ca_certificates(pem: str | None) -> list[x509.Certificate]:
    if not pem or not pem.strip():
        return []
    return x509.load_pem_x509_certificates(pem.encode("utf-8"))


def _verify_one_signature(cert: x509.Certificate, signature: bytes, data: bytes, hash_cls) -> bool:
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hash_cls())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hash_cls()))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _chain_reaches(signer: x509.Certificate, pool: list[x509.Certificate], anchors: list[x509.Certificate]) -> bool:
    """True when signer is one of the supplied certificates or is issued, directly or through the certificates
    carried in the token, by one of them."""
    anchor_fingerprints = {c.fingerprint(hashes.SHA256()) for c in anchors}
    current = signer
    for _ in range(6):
        if current.fingerprint(hashes.SHA256()) in anchor_fingerprints:
            return True
        for ca in anchors:
            try:
                current.verify_directly_issued_by(ca)
                return True
            except Exception:
                continue
        nxt = None
        for candidate in pool:
            if candidate.fingerprint(hashes.SHA256()) == current.fingerprint(hashes.SHA256()):
                continue
            try:
                current.verify_directly_issued_by(candidate)
                nxt = candidate
                break
            except Exception:
                continue
        if nxt is None:
            return False
        current = nxt
    return False


def check_signature(token: bytes, ca_pem: str | None) -> dict:
    """{"signature": "verified" | "timestamp_unverified_signature" | "failed", "detail": ...}

    verified only when a certificate was supplied and: the CMS signature verifies against a certificate
    carried in the token, that certificate chains to one the user supplied, was valid at genTime and may
    sign timestamps. With no certificate supplied the signature is not checked at all."""
    anchors = load_ca_certificates(ca_pem)
    if not anchors:
        return {"signature": SIGNATURE_UNVERIFIED, "detail": "no certificate was supplied to check the signature against"}
    try:
        info = read_token(token)
        buf = info["buf"]
        certs = [x509.load_der_x509_certificate(c) for c in info["certificates"]]
        signer_start, signer_end = info["signer_infos"]
        signer_tlv = _child_with_header(buf, signer_start, signer_end)[0]
        fields = _child_with_header(buf, signer_tlv[2], signer_tlv[3])
        # version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
        digest_alg = _children(buf, fields[2][2], fields[2][3])
        hash_cls = _HASHES.get(_oid_text(buf[digest_alg[0][1]:digest_alg[0][2]]))
        if hash_cls is None:
            return {"signature": SIGNATURE_FAILED, "detail": "unsupported digest algorithm"}
        index = 3
        if fields[index][0] == 0xA0:
            attrs = fields[index]
            signed_bytes = b"\x31" + buf[attrs[1] + 1:attrs[3]]  # re-tag [0] as SET OF for the signature
            digest_ok = False
            for _t, h, s, e in _child_with_header(buf, attrs[2], attrs[3]):
                parts = _children(buf, s, e)
                if _oid_text(buf[parts[0][1]:parts[0][2]]) == OID_MESSAGE_DIGEST:
                    values = _children(buf, parts[1][1], parts[1][2])
                    wanted = buf[values[0][1]:values[0][2]]
                    digest_ok = wanted == hashlib.new(hash_cls.name, info["tst_info"]).digest()
            if not digest_ok:
                return {"signature": SIGNATURE_FAILED, "detail": "the signed message digest does not match the timestamp data"}
            index += 1
        else:
            signed_bytes = info["tst_info"]
        signature = buf[fields[index + 1][2]:fields[index + 1][3]]

        signer = None
        for candidate in certs + anchors:
            if _verify_one_signature(candidate, signature, signed_bytes, hash_cls):
                signer = candidate
                break
        if signer is None:
            return {"signature": SIGNATURE_FAILED, "detail": "the timestamp signature does not verify"}
        if not _chain_reaches(signer, certs, anchors):
            return {"signature": SIGNATURE_FAILED, "detail": "the signing certificate does not chain to the certificate you supplied"}
        if not (signer.not_valid_before_utc <= info["gen_time"] <= signer.not_valid_after_utc):
            return {"signature": SIGNATURE_FAILED, "detail": "the signing certificate was not valid at the timestamp time"}
        try:
            usage = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.TIME_STAMPING not in usage:
                return {"signature": SIGNATURE_FAILED, "detail": "the signing certificate is not for timestamping"}
        except x509.ExtensionNotFound:
            pass
        return {"signature": SIGNATURE_VERIFIED, "detail": "checked against the certificate you supplied"}
    except Exception as exc:
        return {"signature": SIGNATURE_FAILED, "detail": f"the token could not be checked: {exc}"}


# ------------------------------------------------------------------ settings

async def _config(conn: aiosqlite.Connection, key: str) -> str | None:
    cur = await conn.execute("SELECT value FROM app_config WHERE key = ?", (key,))
    row = await cur.fetchone()
    return row["value"] if row else None


async def load_settings(conn: aiosqlite.Connection) -> dict:
    return {
        "enabled": (await _config(conn, CONFIG_ENABLED)) == "1",
        "url": ((await _config(conn, CONFIG_URL)) or "").strip(),
        "fallback_url": ((await _config(conn, CONFIG_FALLBACK_URL)) or "").strip(),
        "ca_pem": (await _config(conn, CONFIG_CA_PEM)) or "",
        "since_seq": int((await _config(conn, CONFIG_SINCE_SEQ)) or 0),
    }


def is_active(settings: dict) -> bool:
    """Both the switch and a URL are needed; until then nothing is sent."""
    return bool(settings["enabled"] and settings["url"])


# ------------------------------------------------------------------ the queue

def _text(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _delay_for(attempts: int) -> int:
    return BACKOFF_SECONDS[min(max(attempts, 1), len(BACKOFF_SECONDS)) - 1]


async def _http_post(url: str, body: bytes) -> bytes:
    import httpx

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False) as client:
        response = await client.post(
            url, content=body,
            headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
        )
        response.raise_for_status()
        return response.content


async def run_queue(*, db_path=None, post=None, now: datetime | None = None) -> dict:
    """Asks the timestamp service for a token for each anchor that has none and is due. Does nothing unless
    the setting is on and a URL is set. Never raises. `post(url, body) -> bytes` is injectable for tests.

    Which anchors: the ones that are pending or failed (retried when next_try_at has passed), and the ones
    recorded since timestamping was turned on. Older local anchors are not back-filled: a later token covers
    them, because each anchor carries the hash of the one before it. At most MAX_PER_RUN per run, oldest first.

    status: local_only (never tried) -> timestamped (token stored) | pending (the service could not be
    reached: kept and retried, never dropped) | failed (the service answered but the reply was refused,
    malformed or for a different hash; still retried at the slowest interval). attempts counts every try."""
    outcome = {"attempted": 0, "timestamped": 0, "pending": 0, "failed": 0, "skipped": None}
    try:
        from core import evidence_anchor

        conn = await evidence_anchor.connect(db_path)
        try:
            settings = await load_settings(conn)
            if not is_active(settings):
                outcome["skipped"] = "off"
                return outcome
            current = now or datetime.now(timezone.utc)
            cur = await conn.execute(
                "SELECT anchor_seq, anchor_hash, attempts FROM evidence_anchors "
                "WHERE status IN ('pending', 'failed') OR (status = 'local_only' AND anchor_seq >= ?) "
                "ORDER BY anchor_seq ASC", (settings["since_seq"] or 1,),
            )
            rows = [r for r in await cur.fetchall()]
            due = []
            for row in rows:
                cur = await conn.execute("SELECT next_try_at FROM evidence_anchors WHERE anchor_seq = ?", (row["anchor_seq"],))
                next_try = (await cur.fetchone())["next_try_at"]
                if next_try is None or next_try <= _text(current):
                    due.append(row)
            sender = post or _http_post
            for row in due[:MAX_PER_RUN]:
                outcome["attempted"] += 1
                await _attempt(conn, row, settings, sender, current, outcome)
        finally:
            await conn.close()
    except Exception:
        logger.exception("external timestamp queue failed -- monitoring is unaffected")
    return outcome


async def _attempt(conn, row, settings: dict, sender, current: datetime, outcome: dict) -> None:
    anchor_hash = row["anchor_hash"]
    attempts = row["attempts"] + 1
    urls = [u for u in (settings["url"], settings["fallback_url"]) if u]
    request = build_request(anchor_hash)
    last_error, kind = "no reply", "pending"
    for url in urls:
        try:
            reply = await sender(url, request)
        except Exception as exc:  # offline, timeout, DNS, HTTP error: the service was not reached
            last_error, kind = f"{type(exc).__name__}: {exc}"[:300], "pending"
            continue
        try:
            token = parse_response(reply)["token"]
            gen_time = check_imprint(token, anchor_hash)
        except TimestampError as exc:
            last_error, kind = str(exc)[:300], "failed"
            continue
        await conn.execute(
            "UPDATE evidence_anchors SET status = 'timestamped', attempts = ?, next_try_at = NULL, tsa_token = ?, "
            "tsa_name = ?, timestamped_at = ?, error = NULL WHERE anchor_seq = ?",
            (attempts, token, url, gen_time.strftime("%Y-%m-%dT%H:%M:%SZ"), row["anchor_seq"]),
        )
        await conn.commit()
        outcome["timestamped"] += 1
        return
    delay = _delay_for(attempts) if kind == "pending" else BACKOFF_SECONDS[-1]
    await conn.execute(
        "UPDATE evidence_anchors SET status = ?, attempts = ?, next_try_at = ?, error = ? WHERE anchor_seq = ?",
        (kind, attempts, _text(current + timedelta(seconds=delay)), last_error, row["anchor_seq"]),
    )
    await conn.commit()
    outcome[kind] += 1
    logger.info("external timestamp for anchor %s: %s (%s); next try in %ss", row["anchor_seq"], kind, last_error, delay)
