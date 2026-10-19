#!/usr/bin/env python3
"""vigil_verify: check a Vigil evidence bundle offline.

Usage:  python vigil_verify.py <bundle.zip> [--tsa-ca <pem>] [--trust-key <fingerprint>]

Uses only the Python standard library and the `cryptography` package. It does not import anything from
Vigil, opens no network connection and reads no file except the bundle and the optional files named on the
command line. The format it checks is written down in docs/design/evidence-bundle-spec.md, so a third party
can reimplement it.

Each check prints PASS, FAIL or NOT CHECKED. Exit code: 0 nothing failed and nothing was left unchecked,
1 at least one check failed, 2 nothing failed but at least one check could not be made, 3 the input is not
a readable bundle.

What a clean result establishes: the files are the ones the manifest lists, the manifest is signed by the
key it names, the exported events re-hash into the chain the manifest describes, and the anchors recorded
for that chain agree with it. What it does not establish: who exported the bundle (the signing key is
readable by the user Vigil runs as), that the events are true or complete, anything about events after the
newest timestamp, or anything about alerts, sessions or audit entries.
"""

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID
except ImportError:  # pragma: no cover
    print("vigil_verify needs the 'cryptography' package (pip install cryptography).", file=sys.stderr)
    sys.exit(3)

SPEC = "vigil-evidence-bundle-1"
SUPPORTED_VERIFIER_SPEC = 1
GENESIS = "0" * 64
PROOF, SIGNATURE = "chain-proof.json", "chain-proof.sig"
EVENT_COLUMNS = (
    "id", "agent_id", "session_id", "event_type", "path", "detail", "file_count", "data_volume_bytes",
    "severity", "anomaly_score", "pid", "behaviour_score", "event_source", "created_at",
)

PASS, FAIL, UNCHECKED = "PASS", "FAIL", "NOT CHECKED"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, message: str) -> None:
    results.append((status, name, message))
    print(f"{status:<12} {name}: {message}")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------ minimal DER (for the timestamp tokens)

class DerError(Exception):
    pass


def _read(buf, pos=0):
    try:
        tag = buf[pos]
        length = buf[pos + 1]
        start = pos + 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4:
                raise DerError("unsupported length")
            length = int.from_bytes(buf[start:start + count], "big")
            start += count
        end = start + length
        if end > len(buf):
            raise DerError("element runs past the end")
        return tag, start, end
    except IndexError:
        raise DerError("truncated") from None


def _items(buf, start, end):
    """(tag, header_start, content_start, content_end) for each element in buf[start:end]."""
    out, pos = [], start
    while pos < end:
        tag, s, e = _read(buf, pos)
        out.append((tag, pos, s, e))
        pos = e
    return out


def _oid(content: bytes) -> str:
    parts = [content[0] // 40, content[0] % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
HASHES = {"2.16.840.1.101.3.4.2.1": hashes.SHA256, "2.16.840.1.101.3.4.2.2": hashes.SHA384, "2.16.840.1.101.3.4.2.3": hashes.SHA512}


def read_token(token: bytes) -> dict:
    """The imprint, genTime and signature material of a CMS timestamp token. No signature is checked here."""
    outer = _read(token, 0)
    top = _items(token, outer[1], outer[2])
    if len(top) < 2 or top[0][0] != 0x06 or _oid(token[top[0][2]:top[0][3]]) != OID_SIGNED_DATA or top[1][0] != 0xA0:
        raise DerError("not a CMS SignedData token")
    sd = _read(token, top[1][2])
    kids = _items(token, sd[1], sd[2])
    if len(kids) < 4 or kids[2][0] != 0x30:
        raise DerError("SignedData is incomplete")
    encap = _items(token, kids[2][2], kids[2][3])
    if len(encap) < 2 or encap[1][0] != 0xA0:
        raise DerError("no TSTInfo")
    octets = _read(token, encap[1][2])
    tst = token[octets[1]:octets[2]]
    tst_outer = _read(tst, 0)
    tk = _items(tst, tst_outer[1], tst_outer[2])
    if len(tk) < 5 or tk[2][0] != 0x30 or tk[4][0] != 0x18:
        raise DerError("TSTInfo is malformed")
    imprint_parts = _items(tst, tk[2][2], tk[2][3])
    algorithm = _items(tst, imprint_parts[0][2], imprint_parts[0][3])
    text = tst[tk[4][2]:tk[4][3]].decode("ascii", "replace")
    if not text.endswith("Z"):
        raise DerError("genTime is not UTC")
    body, _, frac = text[:-1].partition(".")
    gen_time = datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    certificates, signer_set = [], None
    for tag, h, s, e in kids[3:]:
        if tag == 0xA0:
            certificates = [token[ch:ce] for _t, ch, _cs, ce in _items(token, s, e)]
        elif tag == 0x31:
            signer_set = (s, e)
    if signer_set is None:
        raise DerError("no signer")
    return {
        "imprint_algorithm": _oid(tst[algorithm[0][2]:algorithm[0][3]]), "imprint": tst[imprint_parts[1][2]:imprint_parts[1][3]],
        "gen_time": gen_time, "tst_info": tst, "certificates": certificates, "signer_set": signer_set,
    }


def _verify_signature(cert, signature, data, hash_cls) -> bool:
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


def _reaches(signer, pool, trusted) -> bool:
    fingerprints = {c.fingerprint(hashes.SHA256()) for c in trusted}
    current = signer
    for _ in range(6):
        if current.fingerprint(hashes.SHA256()) in fingerprints:
            return True
        for ca in trusted:
            try:
                current.verify_directly_issued_by(ca)
                return True
            except Exception:
                pass
        step = None
        for candidate in pool:
            if candidate.fingerprint(hashes.SHA256()) == current.fingerprint(hashes.SHA256()):
                continue
            try:
                current.verify_directly_issued_by(candidate)
                step = candidate
                break
            except Exception:
                pass
        if step is None:
            return False
        current = step
    return False


def token_signature(token: bytes, info: dict, trusted: list) -> tuple[bool, str]:
    """True only if the CMS signature verifies, the signing certificate chains to a certificate the user
    supplied, was valid at genTime and may sign timestamps."""
    try:
        certs = [x509.load_der_x509_certificate(c) for c in info["certificates"]]
        signer_info = _items(token, info["signer_set"][0], info["signer_set"][1])[0]
        fields = _items(token, signer_info[2], signer_info[3])
        digest_alg = _items(token, fields[2][2], fields[2][3])
        hash_cls = HASHES.get(_oid(token[digest_alg[0][2]:digest_alg[0][3]]))
        if hash_cls is None:
            return False, "unsupported digest algorithm"
        index = 3
        if fields[index][0] == 0xA0:
            attrs = fields[index]
            signed = b"\x31" + token[attrs[1] + 1:attrs[3]]
            wanted = None
            for _t, _h, s, e in _items(token, attrs[2], attrs[3]):
                parts = _items(token, s, e)
                if _oid(token[parts[0][2]:parts[0][3]]) == OID_MESSAGE_DIGEST:
                    value = _items(token, parts[1][2], parts[1][3])[0]
                    wanted = token[value[2]:value[3]]
            if wanted != hashlib.new(hash_cls.name, info["tst_info"]).digest():
                return False, "the signed message digest does not match the timestamp data"
            index += 1
        else:
            signed = info["tst_info"]
        signature = token[fields[index + 1][2]:fields[index + 1][3]]
        signer = next((c for c in certs + trusted if _verify_signature(c, signature, signed, hash_cls)), None)
        if signer is None:
            return False, "the timestamp signature does not verify"
        if not _reaches(signer, certs, trusted):
            return False, "the signing certificate does not chain to the certificate supplied with --tsa-ca"
        if not (signer.not_valid_before_utc <= info["gen_time"] <= signer.not_valid_after_utc):
            return False, "the signing certificate was not valid at the timestamp time"
        try:
            if ExtendedKeyUsageOID.TIME_STAMPING not in signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                return False, "the signing certificate is not for timestamping"
        except x509.ExtensionNotFound:
            pass
        return True, "signature checked against the certificate supplied with --tsa-ca"
    except Exception as exc:
        return False, f"the token could not be checked: {exc}"


def parse_timestamp_reply(token_b64: str) -> bytes:
    data = base64.b64decode(token_b64)
    outer = _read(data, 0)
    top = _items(data, outer[1], outer[2])
    if top and top[0][0] == 0x30 and len(top) >= 2:  # a TimeStampResp: PKIStatusInfo then the token
        return data[top[1][1]:top[1][3]]
    return data


# ------------------------------------------------------------------ checks

def canonical(event: dict) -> str:
    return "|".join("" if event.get(col) is None else str(event[col]) for col in EVENT_COLUMNS)


def run(bundle_path: str, tsa_ca: str | None, trust_key: str | None) -> int:
    try:
        archive = zipfile.ZipFile(bundle_path)
        names = archive.namelist()
        proof_bytes = archive.read(PROOF)
        signature_text = archive.read(SIGNATURE)
        proof = json.loads(proof_bytes)
    except (OSError, zipfile.BadZipFile, KeyError, ValueError) as exc:
        print(f"This is not a readable Vigil evidence bundle: {exc}", file=sys.stderr)
        return 3
    if proof.get("spec") != SPEC or int(proof.get("verifier_spec_version", 0)) > SUPPORTED_VERIFIER_SPEC:
        print(f"Unsupported bundle format: {proof.get('spec')!r} version {proof.get('verifier_spec_version')!r}.", file=sys.stderr)
        return 3

    print(f"Bundle: {bundle_path}")
    print(f"Install: {proof.get('install_id')}   period: {proof['period']['start']} to {proof['period']['end']} ({proof['period']['basis']})")
    print(f"Created: {proof.get('created_at')}   signing key fingerprint: {proof.get('public_key_fingerprint')}")
    print()

    # ---- files named in the manifest
    listed = proof.get("files", {})
    contents = {}
    bad = False
    for name, expected in listed.items():
        if name not in names:
            record(FAIL, "files", f"{name} is listed in the manifest but is not in the bundle")
            bad = True
            continue
        contents[name] = archive.read(name)
        if sha256_hex(contents[name]) != expected:
            record(FAIL, "files", f"{name} was changed after the manifest was written (its SHA-256 differs from {PROOF})")
            bad = True
    for name in names:
        if name not in listed and name not in (PROOF, SIGNATURE):
            record(FAIL, "files", f"{name} is in the bundle but is not listed in the manifest")
            bad = True
    if not bad:
        record(PASS, "files", f"all {len(listed)} files match the SHA-256 values in {PROOF}")

    # ---- manifest signature
    public_bytes = b""
    try:
        public_bytes = base64.b64decode(proof["public_key"])
        ed25519.Ed25519PublicKey.from_public_bytes(public_bytes).verify(base64.b64decode(signature_text), proof_bytes)
        record(PASS, "signature", f"{PROOF} is signed by the key it names (made without access to that key it could not be edited)")
    except (InvalidSignature, ValueError, KeyError, TypeError):
        record(FAIL, "signature", f"{PROOF} does not match {SIGNATURE} (the manifest was edited, or it was signed by another key)")

    # ---- anchors (parsed once)
    anchors = []
    anchor_problem = False
    previous = None
    for entry in proof.get("anchors", []):
        seq = entry.get("anchor_seq")
        if sha256_hex(entry.get("anchor_json", "").encode("utf-8")) != entry.get("anchor_hash"):
            record(FAIL, "anchors", f"anchor {seq}: its stored hash differs from the hash of its own JSON (the anchor was edited)")
            anchor_problem = True
            continue
        try:
            fields = json.loads(entry["anchor_json"])
        except ValueError:
            record(FAIL, "anchors", f"anchor {seq}: its JSON cannot be read")
            anchor_problem = True
            continue
        if fields.get("anchor_seq") != seq:
            record(FAIL, "anchors", f"anchor {seq}: the sequence number inside the anchor is {fields.get('anchor_seq')}")
            anchor_problem = True
        if fields.get("install_id") != proof.get("install_id"):
            record(FAIL, "anchors", f"anchor {seq} belongs to another install ({fields.get('install_id')}), not {proof.get('install_id')}")
            anchor_problem = True
        if previous is not None:
            if seq != previous["seq"] + 1 or fields.get("prev_anchor_hash") != previous["hash"]:
                record(FAIL, "anchors", f"anchor {seq} does not follow anchor {previous['seq']} (the anchor chain is broken)")
                anchor_problem = True
            if fields.get("event_count", 0) < previous["fields"].get("event_count", 0):
                record(FAIL, "anchors", f"anchor {seq} records fewer sealed events than anchor {previous['seq']}")
                anchor_problem = True
        item = {"seq": seq, "hash": entry["anchor_hash"], "fields": fields, "entry": entry}
        anchors.append(item)
        previous = item
    if not anchor_problem:
        if anchors:
            record(PASS, "anchors", f"{len(anchors)} anchors: each hash matches its JSON, the sequence and previous-hash links hold, all belong to this install")
        else:
            record(UNCHECKED, "anchors", "the bundle holds no anchors")

    # ---- signing key
    fingerprint_ok = hashlib.sha256(public_bytes).hexdigest() == proof.get("public_key_fingerprint")
    keyed = [a for a in anchors if a["fields"].get("key_fingerprint")]
    mismatched = [a for a in keyed if a["fields"]["key_fingerprint"] != proof.get("public_key_fingerprint")]
    if not fingerprint_ok:
        record(FAIL, "key", "the fingerprint in the manifest is not the fingerprint of the public key in the manifest")
    elif mismatched:
        record(FAIL, "key", f"anchor {mismatched[0]['seq']} records a different signing key "
                            f"({mismatched[0]['fields']['key_fingerprint'][:16]}...) than the manifest names")
    elif not keyed:
        record(UNCHECKED, "key", "no anchor records a signing key fingerprint (anchors made before the key existed), so the key is not tied to the anchors")
    else:
        record(PASS, "key", f"the manifest's key fingerprint matches the {len(keyed)} anchors that record one"
                            + (f" ({len(anchors) - len(keyed)} older anchors record none)" if len(keyed) < len(anchors) else ""))
    if trust_key:
        if trust_key.lower() == str(proof.get("public_key_fingerprint")).lower():
            record(PASS, "key-pinned", "the signing key is the fingerprint you supplied with --trust-key")
        else:
            record(FAIL, "key-pinned", "the signing key is not the fingerprint you supplied with --trust-key")
    else:
        print("             note: --trust-key was not given, so nothing here shows this key belongs to the installation you expect")

    # ---- chain
    chain_hash_at = {}
    try:
        text = contents.get("events.jsonl", b"").decode("utf-8")
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (UnicodeDecodeError, ValueError):
        rows = None
    chain_info = proof.get("chain", {})
    if rows is None:
        record(FAIL, "chain", "events.jsonl cannot be read")
    else:
        problem = None
        prev = chain_info.get("prev_hash")
        last_id = None
        for number, row in enumerate(rows, 1):
            event, event_id = row.get("event"), row.get("event_id")
            if event is None:
                problem = f"row {number} (event {event_id}): the event is missing from the export"
                break
            if str(event.get("id")) != str(event_id):
                problem = f"row {number}: the event's id {event.get('id')} is not the id {event_id} its chain row names"
                break
            if last_id is not None and event_id <= last_id:
                problem = f"row {number} (event {event_id}): rows are out of order (event {last_id} came before)"
                break
            if row.get("prev_hash") != prev:
                problem = (f"row {number} (event {event_id}): the link to the previous row is broken "
                           "(a row is missing, reordered or replaced)")
                break
            if sha256_hex((prev + canonical(event)).encode("utf-8")) != row.get("row_hash"):
                problem = f"row {number} (event {event_id}): the event does not re-hash to its stored hash (the event was edited)"
                break
            prev, last_id = row["row_hash"], event_id
            chain_hash_at[event_id] = row["row_hash"]
        if problem is None and len(rows) != chain_info.get("row_count"):
            problem = f"the bundle holds {len(rows)} rows but the manifest says {chain_info.get('row_count')} (rows were removed or added)"
        if problem is None and rows and (rows[0]["event_id"] != chain_info.get("first_event_id") or rows[-1]["event_id"] != chain_info.get("last_event_id")):
            problem = (f"the rows run from event {rows[0]['event_id']} to {rows[-1]['event_id']}, the manifest says "
                       f"{chain_info.get('first_event_id')} to {chain_info.get('last_event_id')} (the range was cut)")
        if problem is None and not rows:
            problem = "events.jsonl holds no rows"
        if problem:
            record(FAIL, "chain", problem)
        else:
            record(PASS, "chain", f"{len(rows)} events re-hashed here, every link holds, from event {rows[0]['event_id']} to {rows[-1]['event_id']}")
    chain_ok = rows is not None and results and not any(s == FAIL and n == "chain" for s, n, _ in results)

    # ---- anchors bind the chain
    first_id, last_event = chain_info.get("first_event_id"), chain_info.get("last_event_id")
    bound, binding_failed = [], False
    for a in anchors:
        at = a["fields"].get("last_event_id")
        if at is None or first_id is None:
            continue
        if first_id <= at <= last_event:
            if not chain_ok:
                continue
            if at not in chain_hash_at:
                record(FAIL, "anchor-binds", f"anchor {a['seq']} records event {at}, which is not in the exported chain")
                binding_failed = True
            elif chain_hash_at[at] != a["fields"].get("chain_head"):
                record(FAIL, "anchor-binds", f"anchor {a['seq']} recorded head {a['fields']['chain_head'][:16]}... at event {at}, "
                                             f"the exported chain has {chain_hash_at[at][:16]}... (the chain was rewritten after the anchor)")
                binding_failed = True
            else:
                bound.append(a)
    covers_end = [a for a in bound if a["fields"]["last_event_id"] >= chain_info.get("range_last_event_id", last_event)]
    if not binding_failed:
        if covers_end:
            record(PASS, "anchor-binds", f"{len(bound)} anchors agree with the chain; anchor {covers_end[0]['seq']} (created "
                                         f"{covers_end[0]['fields']['created_at']}) records the chain head at event {covers_end[0]['fields']['last_event_id']}")
        elif not chain_ok:
            record(UNCHECKED, "anchor-binds", "the chain did not check out, so anchors were not compared with it")
        else:
            record(UNCHECKED, "anchor-binds", "no anchor in the bundle covers the end of the range, so the end of the chain is not bound")

    # ---- timestamp tokens
    trusted = []
    if tsa_ca:
        try:
            with open(tsa_ca, "rb") as fh:
                trusted = x509.load_pem_x509_certificates(fh.read())
        except (OSError, ValueError) as exc:
            print(f"Cannot read the certificate given to --tsa-ca: {exc}", file=sys.stderr)
            return 3
    tokens = [a for a in anchors if a["entry"].get("tsa_token_b64")]
    verified_tokens = []
    if not tokens:
        record(UNCHECKED, "timestamps", "the bundle holds no timestamp tokens")
    for a in tokens:
        seq = a["seq"]
        try:
            token = parse_timestamp_reply(a["entry"]["tsa_token_b64"])
            info = read_token(token)
        except (DerError, ValueError, KeyError) as exc:
            record(FAIL, "timestamps", f"anchor {seq}: the token cannot be read ({exc})")
            continue
        if info["imprint_algorithm"] != OID_SHA256 or info["imprint"] != bytes.fromhex(a["hash"]):
            record(FAIL, "timestamps", f"anchor {seq}: the token's message imprint is not this anchor's hash (the token is for a different anchor or the anchor was edited)")
            continue
        when = info["gen_time"].strftime("%Y-%m-%d %H:%M:%SZ")
        if not trusted:
            record(UNCHECKED, "timestamps", f"anchor {seq}: the imprint matches and the time reads {when}, signature not authenticated "
                                            "(no --tsa-ca certificate was supplied)")
            continue
        ok, detail = token_signature(token, info, trusted)
        if ok:
            record(PASS, "timestamps", f"anchor {seq}: imprint matches, time {when}, {detail}")
            verified_tokens.append((a, info["gen_time"]))
        else:
            record(FAIL, "timestamps", f"anchor {seq}: {detail}")

    # ---- coverage and gaps (shown, never a verdict)
    print()
    try:
        coverage = json.loads(contents.get("coverage.json", b"{}"))
        print(coverage.get("title", "What this report covers"))
        for line in coverage.get("lines", []):
            print(f"  - {line}")
    except ValueError:
        print("  (coverage.json could not be read)")
    try:
        gap_doc = json.loads(contents.get("gaps.json", b"{}"))
        # {"time_basis": "UTC", "gaps": [...]}; a bare list (older bundles) is read the same way
        gaps = gap_doc if isinstance(gap_doc, list) else gap_doc.get("gaps", [])
        basis = "UTC" if isinstance(gap_doc, list) else gap_doc.get("time_basis", "UTC")
    except ValueError:
        gaps, basis = [], "UTC"
    print(f"Monitoring gaps overlapping the period: {len(gaps)} (times in {basis})")
    for gap in gaps[:20]:
        print(f"  - {gap.get('gap_start')} {basis} to {gap.get('gap_end')} {basis} ({gap.get('reason')})")
    print("Anchors are hourly at most: events after the newest anchor, and events Vigil could not see, are outside every check above.")
    print()

    # ---- the plain-language summary
    failed = [r for r in results if r[0] == FAIL]
    unchecked = [r for r in results if r[0] == UNCHECKED]
    if failed:
        print(f"RESULT: FAILED. {len(failed)} check(s) found records that do not match: " + ", ".join(sorted({r[1] for r in failed})) + ".")
        print("Do not rely on this bundle until the cause is known. A mismatch can come from damage or from an edit; this check cannot tell which.")
        code = 1
    elif unchecked:
        print("RESULT: INCONCLUSIVE. Nothing failed, but these checks could not be made: " + ", ".join(sorted({r[1] for r in unchecked})) + ".")
        code = 2
    else:
        print("RESULT: CONSISTENT. Every check passed.")
        code = 0
    if not failed:
        print("Established: " + "; ".join(filter(None, [
            "the files are those the manifest lists and the manifest is signed by the key it names" if not any(r[1] in ("files", "signature") and r[0] != PASS for r in results) else "",
            f"{len(rows)} exported events re-hash into one unbroken chain" if chain_ok and rows else "",
            "the anchors in the bundle agree with that chain" if covers_end else "",
        ])) + ".")
        if verified_tokens and covers_end:
            # Several anchors can share one chain head. The earliest checked timestamp at the head the bundle ends on
            # is the one that says how long the records have been unchanged; a later one says less.
            head = covers_end[0]["fields"]["chain_head"]
            at = covers_end[0]["fields"]["last_event_id"]
            same_head = [t for t in verified_tokens if t[0]["fields"]["chain_head"] == head and t[0]["fields"]["last_event_id"] == at]
            if same_head:
                earliest = min(same_head, key=lambda t: t[1])
                print(f"A timestamp whose signature was checked against the certificate you supplied supports this: events up to event {at} "
                      f"were consistent with the anchor head at {earliest[1].strftime('%Y-%m-%d %H:%M:%SZ')} (the earliest checked timestamp at "
                      "that head) and not altered since that time. The timestamp attests only to the time of the hash.")
            else:
                print("No checked timestamp is at the head the bundle ends on, so no statement is made about when these records last matched.")
        else:
            print("No timestamp with a checked signature supports a statement about when these records last matched; "
                  "the anchors alone are held on the same machine as the events.")
    print("Not established: who exported the bundle (the signing key is readable by the user Vigil runs as); that the events are true "
          "or complete; anything about events after the newest anchor or timestamp; anything about alerts, sessions or audit entries.")
    return code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check a Vigil evidence bundle offline.")
    parser.add_argument("bundle", help="the evidence bundle (.zip)")
    parser.add_argument("--tsa-ca", help="PEM certificate (or chain) of the timestamp service, to check timestamp signatures")
    parser.add_argument("--trust-key", help="the signing-key fingerprint you hold from another source")
    args = parser.parse_args(argv)
    return run(args.bundle, args.tsa_ca, args.trust_key)


if __name__ == "__main__":
    sys.exit(main())
