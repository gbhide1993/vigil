"""Stage 2 (opt-in RFC 3161 timestamps, core/external_timestamp.py). Everything runs against a fake
timestamp service built here from a throwaway key and certificate: no network is used, and the real
HTTP sender is replaced by an injected function (and made to fail loudly where it must not be called)."""

import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import api.export as export_module
import core.evidence_anchor as anchors
import core.evidence_chain as chain
import core.external_timestamp as ts
import db.database as database
from core.evidence_chain import seal_new_events

SCHEMA = Path(database.SCHEMA_PATH)
T0 = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
URL = "https://tsa.example.test/tsr"


# ------------------------------------------------------------------ a fake timestamp service

def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_authority(common_name="Fake TSA CA"):
    """A CA certificate and a timestamping certificate it signs (EC keys, valid around the real clock)."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder().subject_name(_name(common_name)).issuer_name(_name(common_name))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    tsa_key = ec.generate_private_key(ec.SECP256R1())
    tsa_cert = (
        x509.CertificateBuilder().subject_name(_name("Fake TSA")).issuer_name(ca_cert.subject)
        .public_key(tsa_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_cert, tsa_cert, tsa_key


def ca_pem(ca_cert) -> str:
    return ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def imprint_of(request: bytes) -> bytes:
    """The 32 hash bytes in a request, found without trusting the code under test to parse it."""
    index = request.index(b"\x04\x20")
    return request[index + 2:index + 34]


def make_response(request: bytes, ca_cert, tsa_cert, tsa_key, *, gen_time=None, imprint=None, include_certs=True) -> bytes:
    """A TimeStampResp (status granted) with a CMS SignedData token signed by tsa_key."""
    der, oid = ts.der, ts._oid_bytes
    gen_time = gen_time or datetime.now(timezone.utc).replace(microsecond=0)
    digest = imprint if imprint is not None else imprint_of(request)
    sha256 = der(0x30, der(0x06, oid(ts.OID_SHA256)) + der(0x05, b""))
    tst = der(0x30, b"".join([
        der(0x02, b"\x01"), der(0x06, oid("1.2.3.4")),
        der(0x30, sha256 + der(0x04, digest)),
        der(0x02, b"\x2a"), der(0x18, gen_time.strftime("%Y%m%d%H%M%SZ").encode()),
    ]))
    ct_tst = oid("1.2.840.113549.1.9.16.1.4")
    attrs = der(0x30, der(0x06, oid("1.2.840.113549.1.9.3")) + der(0x31, der(0x06, ct_tst))) + \
        der(0x30, der(0x06, oid(ts.OID_MESSAGE_DIGEST)) + der(0x31, der(0x04, hashlib.sha256(tst).digest())))
    signature = tsa_key.sign(der(0x31, attrs), ec.ECDSA(hashes.SHA256()))
    serial = tsa_cert.serial_number.to_bytes(21, "big").lstrip(b"\x00") or b"\x00"
    if serial[0] & 0x80:
        serial = b"\x00" + serial
    signer = der(0x30, b"".join([
        der(0x02, b"\x01"),
        der(0x30, tsa_cert.issuer.public_bytes() + der(0x02, serial)),
        sha256,
        der(0xA0, attrs),
        der(0x30, der(0x06, oid("1.2.840.10045.4.3.2"))),
        der(0x04, signature),
    ]))
    certs = b""
    if include_certs:
        certs = der(0xA0, tsa_cert.public_bytes(serialization.Encoding.DER))
    signed = der(0x30, b"".join([
        der(0x02, b"\x03"), der(0x31, sha256),
        der(0x30, der(0x06, ct_tst) + der(0xA0, der(0x04, tst))),
        certs, der(0x31, signer),
    ]))
    token = der(0x30, der(0x06, oid(ts.OID_SIGNED_DATA)) + der(0xA0, signed))
    return der(0x30, der(0x30, der(0x02, b"\x00")) + token)


class FakeTSA:
    """Records every request it receives. mode: "ok", "offline" (raises), "other_hash" (stamps a different
    hash), "garbage" (a reply that is not a timestamp)."""

    def __init__(self, mode="ok", authority=None):
        self.mode = mode
        self.ca, self.cert, self.key = authority or make_authority()
        self.requests = []
        self.gen_time = None

    async def __call__(self, url, body):
        self.requests.append((url, body))
        if self.mode == "offline":
            raise ConnectionError("network is unreachable")
        if self.mode == "garbage":
            return b"<html>not a timestamp</html>"
        imprint = hashlib.sha256(b"some other hash").digest() if self.mode == "other_hash" else None
        return make_response(body, self.ca, self.cert, self.key, imprint=imprint, gen_time=self.gen_time)


# ------------------------------------------------------------------ a database and a key directory

@pytest.fixture
def env(tmp_path, monkeypatch):
    import types

    db_path = tmp_path / "vlaw.db"
    monkeypatch.setattr(chain, "DB_PATH", db_path)
    monkeypatch.setenv("VLAW_KEY_DIR", str(tmp_path / "keys"))
    export_module._chain_cache["value"] = None
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA.read_text())
    conn.execute("INSERT INTO agents (name, process_name, approved) VALUES ('ts_test_agent', 'x', 1)")
    conn.commit()
    conn.close()

    async def forbidden(url, body):
        raise AssertionError("the real HTTP sender must not be reached in a test")

    monkeypatch.setattr(ts, "_http_post", forbidden)
    yield types.SimpleNamespace(db_path=db_path, keys=tmp_path / "keys")
    export_module._chain_cache["value"] = None


def sql(env, statement, params=()):
    conn = sqlite3.connect(env.db_path)
    try:
        cur = conn.execute(statement, params)
        conn.commit()
        return cur.fetchall()
    finally:
        conn.close()


def configure(env, *, enabled=True, url=URL, fallback="", pem="", since=1):
    for key, value in ((ts.CONFIG_ENABLED, "1" if enabled else "0"), (ts.CONFIG_URL, url), (ts.CONFIG_FALLBACK_URL, fallback),
                       (ts.CONFIG_CA_PEM, pem), (ts.CONFIG_SINCE_SEQ, str(since))):
        sql(env, "INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)", (key, value))


async def add_anchor(env, events=3, minute=0):
    conn = sqlite3.connect(env.db_path)
    for i in range(events):
        conn.execute("INSERT INTO events (agent_id, session_id, event_type, path, created_at) VALUES (1, 's', 'file_write', ?, '2026-10-01 07:00:00')",
                     (f"/tmp/{minute}-{i}.py",))
    conn.commit()
    conn.close()
    while await seal_new_events():
        pass
    return await anchors.create_anchor("export", key_directory=env.keys, now=T0 + timedelta(hours=minute), db_path=env.db_path)


def row(env, seq=1):
    return sql(env, "SELECT status, attempts, next_try_at, tsa_name, timestamped_at, error, length(tsa_token) FROM evidence_anchors WHERE anchor_seq = ?", (seq,))[0]


# ------------------------------------------------------------------ the request

def test_the_request_is_the_digest_and_nothing_else():
    anchor_hash = hashlib.sha256(b"an anchor").hexdigest()
    body = ts.build_request(anchor_hash)
    sha256_algorithm = bytes.fromhex("300d06096086480165030402010500")
    expected = (bytes.fromhex("3039") + bytes.fromhex("020101") + bytes.fromhex("3031") + sha256_algorithm
                + bytes.fromhex("0420") + bytes.fromhex(anchor_hash) + bytes.fromhex("0101ff"))
    assert body == expected, "version 1, the SHA-256 imprint, certReq TRUE; no policy, no nonce, no extensions"
    assert len(body) == 59
    assert body.count(bytes.fromhex(anchor_hash)) == 1
    # the only variable bytes are the 32 hash bytes
    other = ts.build_request(hashlib.sha256(b"another").hexdigest())
    assert [i for i in range(59) if body[i] != other[i]] and all(24 <= i < 56 for i in range(59) if body[i] != other[i])
    with pytest.raises(ValueError):
        ts.build_request("ab" * 31)


def test_the_disclosure_text_is_exactly_the_agreed_wording():
    assert ts.DISCLOSURE == ("When on, Vigil sends only a 32-byte hash of an anchor to the timestamp service you choose. "
                             "No events, file paths or names leave this machine. This is a second outbound connection.")


# ------------------------------------------------------------------ off by default

@pytest.mark.asyncio
async def test_nothing_is_sent_by_default_or_without_a_url(env):
    await add_anchor(env)
    fake = FakeTSA()
    assert (await ts.run_queue(db_path=env.db_path, post=fake))["skipped"] == "off"      # no setting at all
    configure(env, enabled=True, url="")
    assert (await ts.run_queue(db_path=env.db_path, post=fake))["skipped"] == "off"      # on, but no address
    configure(env, enabled=False, url=URL)
    assert (await ts.run_queue(db_path=env.db_path, post=fake))["skipped"] == "off"      # an address, but off
    assert fake.requests == []
    assert row(env)[0] == "local_only" and row(env)[1] == 0
    # the default sender is never reached either (the fixture makes it raise)
    assert (await ts.run_queue(db_path=env.db_path))["skipped"] == "off"


@pytest.mark.asyncio
async def test_the_stored_defaults_are_off_and_empty(env):
    async with __import__("aiosqlite").connect(env.db_path) as conn:
        conn.row_factory = __import__("aiosqlite").Row
        settings = await ts.load_settings(conn)
    assert settings == {"enabled": False, "url": "", "fallback_url": "", "ca_pem": "", "since_seq": 0}
    assert not ts.is_active(settings)


# ------------------------------------------------------------------ the queue

@pytest.mark.asyncio
async def test_a_request_carries_only_the_anchor_hash_and_a_token_is_stored(env):
    anchor = await add_anchor(env)
    configure(env)
    fake = FakeTSA()
    result = await ts.run_queue(db_path=env.db_path, post=fake, now=T0)
    assert result["timestamped"] == 1
    assert len(fake.requests) == 1
    url, body = fake.requests[0]
    assert url == URL and body == ts.build_request(anchor["anchor_hash"])
    assert imprint_of(body) == bytes.fromhex(anchor["anchor_hash"])
    status, attempts, next_try, tsa_name, stamped_at, error, token_len = row(env)
    assert (status, attempts, next_try, tsa_name, error) == ("timestamped", 1, None, URL, None)
    assert token_len > 200 and stamped_at.endswith("Z")
    # a second run has nothing left to do
    assert (await ts.run_queue(db_path=env.db_path, post=fake, now=T0))["attempted"] == 0


@pytest.mark.asyncio
async def test_an_offline_machine_retries_with_backoff_and_never_blocks_anchoring_or_export(env):
    await add_anchor(env)
    configure(env)
    fake = FakeTSA("offline")
    delays = []
    now = T0
    for expected in (60, 300, 1800, 3600, 3600):
        await ts.run_queue(db_path=env.db_path, post=fake, now=now)
        status, attempts, next_try, *_ = row(env)
        assert status == "pending"
        delays.append(int((datetime.strptime(next_try, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - now).total_seconds()))
        now = datetime.strptime(next_try, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert delays == [60, 300, 1800, 3600, 3600] and row(env)[1] == 5
    # not due yet: no new attempt
    sent = len(fake.requests)
    await ts.run_queue(db_path=env.db_path, post=fake, now=now - timedelta(seconds=30))
    assert len(fake.requests) == sent

    # while the service is unreachable, anchoring and the export check still work
    second = await add_anchor(env, minute=1)
    assert second["anchor_seq"] == 2 and row(env, 2)[0] == "local_only"
    export_module._chain_cache["value"] = None
    verification = await export_module._chain_verification(fresh=True)
    assert verification["status"] == "consistent" and verification["anchors_checked"] >= 2
    assert verification["timestamps"]["status"] == "local_only"
    assert verification["timestamps"]["waiting"] >= 1


@pytest.mark.asyncio
async def test_a_late_stamp_reports_the_stamp_time_not_the_creation_time(env):
    await add_anchor(env)
    configure(env)
    await ts.run_queue(db_path=env.db_path, post=FakeTSA("offline"), now=T0)
    late = FakeTSA()
    late.gen_time = T0 + timedelta(days=3)
    await ts.run_queue(db_path=env.db_path, post=late, now=T0 + timedelta(minutes=2))
    status, attempts, next_try, tsa_name, stamped_at, *_ = row(env)
    assert (status, attempts) == ("timestamped", 2)
    assert stamped_at == "2026-10-04T08:00:00Z"
    result = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert result["timestamps"]["latest"]["tsa_time"] == "2026-10-04T08:00:00Z"


@pytest.mark.asyncio
async def test_a_token_for_a_different_hash_is_rejected_and_not_stored(env):
    await add_anchor(env)
    configure(env)
    result = await ts.run_queue(db_path=env.db_path, post=FakeTSA("other_hash"), now=T0)
    assert result["failed"] == 1 and result["timestamped"] == 0
    status, attempts, next_try, tsa_name, stamped_at, error, token_len = row(env)
    assert status == "failed" and attempts == 1 and token_len is None and "not this anchor's hash" in error
    garbage = await ts.run_queue(db_path=env.db_path, post=FakeTSA("garbage"), now=T0 + timedelta(hours=2))
    assert garbage["failed"] == 1 and row(env)[1] == 2

    fake = FakeTSA()
    request = ts.build_request(hashlib.sha256(b"x").hexdigest())
    reply = make_response(request, fake.ca, fake.cert, fake.key, imprint=hashlib.sha256(b"y").digest())
    token = ts.parse_response(reply)["token"]
    with pytest.raises(ts.TimestampError):
        ts.check_imprint(token, hashlib.sha256(b"x").hexdigest())
    assert ts.check_imprint(token, hashlib.sha256(b"y").hexdigest())


@pytest.mark.asyncio
async def test_the_fallback_address_is_tried_only_after_the_first_fails(env):
    await add_anchor(env)
    configure(env, fallback="https://backup.example.test/tsr")
    calls = []
    good = FakeTSA()

    async def flaky(url, body):
        calls.append(url)
        if url == URL:
            raise TimeoutError("slow")
        return await good(url, body)

    await ts.run_queue(db_path=env.db_path, post=flaky, now=T0)
    assert calls == [URL, "https://backup.example.test/tsr"] and row(env)[3] == "https://backup.example.test/tsr"


# ------------------------------------------------------------------ checking tokens

@pytest.mark.asyncio
async def test_status_moves_from_local_only_to_partially_to_externally_timestamped(env):
    none = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert none["anchoring"] == "none" and none["timestamps"]["status"] == "none"

    await add_anchor(env)
    configure(env)
    local = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert local["anchoring"] == "local_only" and local["timestamps"]["status"] == "local_only"
    assert local["timestamps"]["recent"][-1]["status"] == "local_only"

    fake = FakeTSA()
    await ts.run_queue(db_path=env.db_path, post=fake, now=T0)
    full = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert full["timestamps"]["status"] == "externally_timestamped" and full["anchoring"] == "externally_timestamped"
    assert full["timestamps"]["latest"]["anchor_seq"] == 1 and full["timestamps"]["recent"][-1]["status"] == "externally_timestamped"

    await add_anchor(env, minute=1)
    partial = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert partial["timestamps"]["status"] == "partially_timestamped" and partial["anchoring"] == "partially_timestamped"
    assert partial["timestamps"]["timestamped"] == 1 and partial["timestamps"]["waiting"] == 1

    await ts.run_queue(db_path=env.db_path, post=fake, now=T0 + timedelta(minutes=5))
    again = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert again["timestamps"]["status"] == "externally_timestamped" and again["timestamps"]["latest"]["anchor_seq"] == 2


@pytest.mark.asyncio
async def test_an_anchor_changed_after_it_was_timestamped_is_a_mismatch(env):
    anchor = await add_anchor(env)
    configure(env)
    await ts.run_queue(db_path=env.db_path, post=FakeTSA(), now=T0)
    assert (await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys))["status"] == "ok"

    # An attacker edits the anchor (here its table digest) and keeps the row consistent with itself: new JSON, new hash.
    import json

    changed = json.loads(sql(env, "SELECT anchor_json FROM evidence_anchors WHERE anchor_seq = 1")[0][0])
    changed["tables_digest"] = "0" * 64
    new_json = anchors.canonical_json(changed)
    new_hash = anchors.anchor_hash_of(new_json)
    sql(env, "UPDATE evidence_anchors SET anchor_json = ?, anchor_hash = ? WHERE anchor_seq = 1", (new_json, new_hash))
    assert anchor["anchor_hash"] != new_hash
    result = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    # every local check still passes; only the token no longer matches the anchor it was issued for
    assert result["status"] == "timestamp_mismatch" and result["first_mismatch"]["kind"] == "timestamp"
    assert result["anchors_mismatched"] == 1
    assert result["timestamps"]["status"] == "local_only" and result["timestamps"]["timestamped"] == 0, "a token that no longer matches is not counted"
    verification = await chain.verify_chain()
    assert verification["valid"] is False and verification["status"] == "timestamp_mismatch"


@pytest.mark.asyncio
async def test_a_token_that_no_longer_matches_makes_the_timestamp_mismatch_status(env):
    """Only the timestamp token disagrees (the chain and the anchor row agree with each other)."""
    await add_anchor(env)
    configure(env)
    fake = FakeTSA()
    await ts.run_queue(db_path=env.db_path, post=fake, now=T0)
    other = make_response(ts.build_request(hashlib.sha256(b"someone else").hexdigest()), fake.ca, fake.cert, fake.key)
    sql(env, "UPDATE evidence_anchors SET tsa_token = ? WHERE anchor_seq = 1", (ts.parse_response(other)["token"],))
    result = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert result["status"] == "timestamp_mismatch" and result["first_mismatch"]["kind"] == "timestamp"
    assert "does not match the anchor" in result["first_mismatch"]["detail"]


def test_the_signature_is_checked_only_against_a_certificate_the_user_supplied():
    fake = FakeTSA()
    request = ts.build_request(hashlib.sha256(b"a").hexdigest())
    token = ts.parse_response(make_response(request, fake.ca, fake.cert, fake.key))["token"]

    unverified = ts.check_signature(token, None)
    assert unverified["signature"] == ts.SIGNATURE_UNVERIFIED == "timestamp_unverified_signature"
    assert ts.check_signature(token, "")["signature"] == "timestamp_unverified_signature"

    assert ts.check_signature(token, ca_pem(fake.ca))["signature"] == ts.SIGNATURE_VERIFIED
    # a different authority's certificate does not vouch for it
    stranger, _cert, _key = make_authority("Some Other CA")
    assert ts.check_signature(token, ca_pem(stranger))["signature"] == ts.SIGNATURE_FAILED
    # a flipped byte in the signature fails
    broken = bytearray(token)
    broken[-5] ^= 0xFF
    assert ts.check_signature(bytes(broken), ca_pem(fake.ca))["signature"] == ts.SIGNATURE_FAILED
    # a token whose signing certificate is not in the token still verifies if the user supplied it as the trust anchor
    bare = ts.parse_response(make_response(request, fake.ca, fake.cert, fake.key, include_certs=False))["token"]
    both = ca_pem(fake.ca) + fake.cert.public_bytes(serialization.Encoding.PEM).decode()
    assert ts.check_signature(bare, both)["signature"] == ts.SIGNATURE_VERIFIED


@pytest.mark.asyncio
async def test_check_reports_unverified_without_a_certificate_and_verified_with_one(env):
    await add_anchor(env)
    fake = FakeTSA()
    configure(env)
    await ts.run_queue(db_path=env.db_path, post=fake, now=T0)
    without = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert without["timestamps"]["latest"]["signature"] == "timestamp_unverified_signature"
    configure(env, pem=ca_pem(fake.ca))
    with_ca = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert with_ca["timestamps"]["latest"]["signature"] == "verified"
    configure(env, pem=ca_pem(make_authority("Wrong CA")[0]))
    wrong = await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys)
    assert wrong["status"] == "timestamp_mismatch" and "signature" in wrong["first_mismatch"]["detail"]


# ------------------------------------------------------------------ the report wording

@pytest.mark.asyncio
async def test_the_report_lines_for_each_state_never_overclaim(env):
    fake = FakeTSA()
    await add_anchor(env)
    local = export_module._chain_lines(await export_module._chain_verification(fresh=True))
    assert export_module.NO_ANCHORING_LINE in local, "no token: the 'Anchoring: none' line stays"

    configure(env)
    await ts.run_queue(db_path=env.db_path, post=fake, now=T0)
    stamped = export_module._chain_lines(await export_module._chain_verification(fresh=True))
    text = "\n".join(stamped)
    assert f"carry a timestamp issued by {URL}" in text
    assert "anchored locally only and are not yet externally protected" in text
    assert "timestamp_unverified_signature" in text and "was not checked because no certificate was supplied" in text
    assert export_module.NO_ANCHORING_LINE not in stamped

    configure(env, pem=ca_pem(fake.ca))
    export_module._chain_cache["value"] = None
    checked = "\n".join(export_module._chain_lines(await export_module._chain_verification(fresh=True)))
    assert "Timestamp signature: checked against the certificate you supplied" in checked
    assert "timestamp_unverified_signature" not in checked

    await add_anchor(env, minute=1)
    waiting = "\n".join(export_module._chain_lines(await export_module._chain_verification(fresh=True)))
    assert "waiting for timestamp" in waiting.lower() and "not yet externally protected" in waiting

    for text in (local and "\n".join(local), "\n".join(stamped), checked, waiting):
        lowered = text.lower()
        for phrase in ("verified by", "tamper", "cannot be altered", "authority verified"):
            assert phrase not in lowered, (phrase, text)


# ------------------------------------------------------------------ migration and settings

@pytest.mark.asyncio
async def test_the_migration_adds_the_columns_to_an_older_table(tmp_path):
    import aiosqlite

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA.read_text())
    conn.execute("DROP TABLE evidence_anchors")
    conn.execute("CREATE TABLE evidence_anchors (anchor_seq INTEGER PRIMARY KEY, anchor_json TEXT NOT NULL, anchor_hash TEXT NOT NULL, "
                 "prev_anchor_hash TEXT NOT NULL, chain_head TEXT NOT NULL, event_count INTEGER NOT NULL, last_event_id INTEGER NOT NULL, "
                 "tables_digest TEXT NOT NULL, install_id TEXT NOT NULL, created_at TEXT NOT NULL, trigger TEXT NOT NULL, "
                 "status TEXT NOT NULL DEFAULT 'local_only')")
    conn.execute("INSERT INTO evidence_anchors VALUES (1, '{}', 'h', 'p', 'c', 1, 1, 'd', 'i', 't', 'hourly', 'local_only')")
    conn.commit()
    conn.close()
    async with aiosqlite.connect(path) as db:
        db.row_factory = aiosqlite.Row
        await database._migrate(db)
        await database._migrate(db)  # idempotent
        cur = await db.execute("PRAGMA table_info(evidence_anchors)")
        names = {r["name"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT attempts, status, tsa_token FROM evidence_anchors")
        kept = await cur.fetchone()
    assert {"attempts", "next_try_at", "tsa_token", "tsa_name", "timestamped_at", "error"} <= names
    assert (kept["attempts"], kept["status"], kept["tsa_token"]) == (0, "local_only", None), "existing rows are untouched"


@pytest.mark.asyncio
async def test_the_settings_api_defaults_to_off_and_validates(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.config_api as config_api

    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    await database.get_db()
    try:
        app = FastAPI()
        app.include_router(config_api.router)
        client = TestClient(app)
        default = client.get("/config/external-timestamp").json()
        assert default["enabled"] is False and default["url"] == "" and default["active"] is False
        assert default["disclosure"] == ts.DISCLOSURE

        assert client.post("/config/external-timestamp", json={"enabled": True, "url": ""}).status_code == 400
        assert client.post("/config/external-timestamp", json={"enabled": True, "url": "ftp://x"}).status_code == 400
        assert client.post("/config/external-timestamp", json={"enabled": False, "ca_pem": "not a pem"}).status_code == 400
        assert client.get("/config/external-timestamp").json()["enabled"] is False, "a rejected save changes nothing"

        fake = FakeTSA()
        ok = client.post("/config/external-timestamp", json={"enabled": True, "url": URL, "ca_pem": ca_pem(fake.ca)}).json()
        assert ok["enabled"] is True and ok["active"] is True and ok["url"] == URL
        off = client.post("/config/external-timestamp", json={"enabled": False, "url": URL}).json()
        assert off["active"] is False
    finally:
        await database.close_db()
