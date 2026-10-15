"""Stage 3: the signing key, the signed evidence bundle and the standalone verifier (verifier/vigil_verify.py).

The verifier always runs as a subprocess with `python -I`, from a temp directory that holds only a copy of
the verifier and the bundle, so it cannot reach the backend. Timestamp tokens come from the fake service of
test_external_timestamp.py (a throwaway key and certificate); nothing touches the network."""

import base64
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import core.evidence_anchor as anchors
import core.evidence_bundle as evidence_bundle
import core.external_timestamp as ts
import core.signing_key as signing_key
from test_external_timestamp import FakeTSA, add_anchor, ca_pem, configure, env, make_authority, sql  # noqa: F401  (env is a fixture)

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "verifier" / "vigil_verify.py"
T0 = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
DAY = "2026-10-01"


# ------------------------------------------------------------------ helpers

async def make_bundle(env, *, stamp=True, batches=1, authority=None):
    """Events, anchors (stamped by the fake service when stamp is true) and the bundle for DAY."""
    fake = FakeTSA(authority=authority)
    configure(env)
    for i in range(batches):
        await add_anchor(env, events=4, minute=i)
        if stamp:
            await ts.run_queue(db_path=env.db_path, post=fake, now=T0 + timedelta(minutes=i))
    data, summary = await evidence_bundle.build_bundle(DAY, DAY, db_path=env.db_path, key_directory=env.keys, now=T0 + timedelta(hours=5))
    return data, summary, fake


def unpack(data: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {name: z.read(name) for name in z.namelist()}


def repack(files: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buffer.getvalue()


def forge(env, data: bytes, *, events=None, proof=None, extra=None, key_dir=None, resign=True, rehash=True, sign_with=None) -> bytes:
    """What a same-user attacker can do: change a file, fix the manifest's hash for it and sign the manifest
    again with the install's own key (it is readable by the user). resign=False / rehash=False leave those
    steps undone."""
    files = unpack(data)
    manifest = json.loads(files["chain-proof.json"])
    if events is not None:
        lines = files["events.jsonl"].decode().splitlines()
        lines = events(lines)
        files["events.jsonl"] = ("\n".join(lines) + "\n").encode()
        if rehash:
            manifest["files"]["events.jsonl"] = hashlib.sha256(files["events.jsonl"]).hexdigest()
    if proof is not None:
        proof(manifest)
    for name, content in (extra or {}).items():
        files[name] = content
    body = json.dumps(manifest, indent=2, sort_keys=True).encode()
    files["chain-proof.json"] = body
    if resign:
        signature = sign_with.sign(body) if sign_with else signing_key.sign(key_dir or env.keys, body)
        files["chain-proof.sig"] = base64.b64encode(signature)
    return repack(files)


def run_verifier(tmp_path, bundle: bytes, *args, name="bundle.zip", wrapper=None):
    """python -I from a directory holding only the verifier and the bundle."""
    work = tmp_path / f"run_{len(list(tmp_path.glob('run_*')))}"
    work.mkdir()
    shutil.copy(VERIFIER, work / "vigil_verify.py")
    (work / name).write_bytes(bundle)
    command = [sys.executable, "-I", "vigil_verify.py" if wrapper is None else wrapper, name, *args]
    if wrapper is not None:
        (work / wrapper).write_text(WRAPPER_SOURCE, encoding="utf-8")
    result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
    return result.returncode, result.stdout + result.stderr


WRAPPER_SOURCE = '''
import runpy, socket, sys
def refuse(*a, **k):
    raise RuntimeError("NETWORK ACCESS ATTEMPTED")
socket.socket = refuse
socket.create_connection = refuse
socket.getaddrinfo = refuse
sys.argv = ["vigil_verify.py"] + sys.argv[1:]
runpy.run_path("vigil_verify.py", run_name="__main__")
'''


def lines_with(output, status, name):
    return [l for l in output.splitlines() if l.startswith(status) and f" {name}:" in l]


# ------------------------------------------------------------------ the signing key

def test_the_key_is_created_once_stored_in_the_key_directory_and_only_the_public_part_is_exportable(tmp_path):
    first = signing_key.ensure_key(tmp_path, "install-1")
    second = signing_key.ensure_key(tmp_path, "other-id-ignored")
    assert first == second and first["install_id"] == "install-1"
    public = base64.b64decode(first["public_key"])
    assert len(public) == 32 and first["fingerprint"] == hashlib.sha256(public).hexdigest()
    signature = signing_key.sign(tmp_path, b"message")
    ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, b"message")
    assert (tmp_path / "install.key").exists() and (tmp_path / "install.pub.json").exists()
    assert "key" not in json.loads((tmp_path / "install.pub.json").read_text()), "the public record carries no private material"
    if sys.platform == "win32":
        assert first["protection"] == "dpapi"
        stored = json.loads((tmp_path / "install.key").read_text())
        raw_seed = signing_key.load_private(tmp_path).private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        assert base64.b64decode(stored["key"]) != raw_seed, "wrapped with DPAPI, not stored as the raw seed"


@pytest.mark.asyncio
async def test_new_anchors_carry_the_key_fingerprint_and_old_anchors_still_verify(env):
    await add_anchor(env)
    row = sql(env, "SELECT anchor_json FROM evidence_anchors WHERE anchor_seq = 1")[0][0]
    fields = json.loads(row)
    assert fields["v"] == 2 and fields["key_fingerprint"] == signing_key.public_fingerprint(env.keys)

    # an anchor written before Stage 3 (format v1, no fingerprint) in the same series
    old = {k: v for k, v in fields.items() if k != "key_fingerprint"}
    old["v"] = 1
    old_json = anchors.canonical_json(old)
    sql(env, "UPDATE evidence_anchors SET anchor_json = ?, anchor_hash = ? WHERE anchor_seq = 1", (old_json, anchors.anchor_hash_of(old_json)))
    state = anchors.load_state(env.keys)
    state["last_anchor_hash"] = anchors.anchor_hash_of(old_json)
    anchors.save_state(state, env.keys)
    assert (await anchors.check_anchors(db_path=env.db_path, key_directory=env.keys))["status"] == "ok"


# ------------------------------------------------------------------ a clean bundle

@pytest.mark.asyncio
async def test_a_clean_bundle_passes_every_check_and_exits_zero(env, tmp_path):
    data, summary, fake = await make_bundle(env)
    work = tmp_path / "clean"
    work.mkdir()
    shutil.copy(VERIFIER, work / "vigil_verify.py")
    (work / "bundle.zip").write_bytes(data)
    (work / "tsa-ca.pem").write_text(ca_pem(fake.ca))
    result = subprocess.run([sys.executable, "-I", "vigil_verify.py", "bundle.zip", "--tsa-ca", "tsa-ca.pem", "--trust-key", summary["fingerprint"]],
                            cwd=work, capture_output=True, text=True, timeout=120)
    out = result.stdout + result.stderr
    assert result.returncode == 0, out
    for name in ("files", "signature", "anchors", "key", "chain", "anchor-binds", "timestamps", "key-pinned"):
        assert lines_with(out, "PASS", name), (name, out)
    assert "NOT CHECKED" not in out and "FAIL" not in out.replace("RESULT: CONSISTENT", "")
    assert "RESULT: CONSISTENT" in out
    assert "not altered since" in out and "Not established: who exported the bundle" in out
    assert "What this report covers" in out and "File reads are not recorded." in out
    assert "Monitoring gaps overlapping the period: 0" in out


@pytest.mark.asyncio
async def test_the_bundle_holds_only_the_listed_files_and_no_secrets(env):
    data, summary, fake = await make_bundle(env)
    files = unpack(data)
    assert set(files) == {"chain-proof.json", "chain-proof.sig", "events.jsonl", "coverage.json", "gaps.json"}
    private = json.loads((env.keys / "install.key").read_text())["key"]
    whole = b"".join(files.values()).decode("utf-8", "replace")
    assert private not in whole
    for word in ("external_timestamp_ca_pem", "webhook", "VLAW_KEY_DIR", "app_config"):
        assert word not in whole
    proof = json.loads(files["chain-proof.json"])
    assert proof["public_key_fingerprint"] == signing_key.public_fingerprint(env.keys)
    assert set(proof["files"]) == {"events.jsonl", "coverage.json", "gaps.json"}
    assert proof["chain"]["row_count"] == 4 and proof["chain"]["prev_hash"] == "0" * 64
    assert summary["tokens"] == 1 and summary["bound_by_anchor"] == 1


@pytest.mark.asyncio
async def test_without_a_ca_certificate_the_token_is_not_checked_never_passed(env, tmp_path):
    data, summary, fake = await make_bundle(env)
    code, out = run_verifier(tmp_path, data)
    assert code == 2, out
    line = lines_with(out, "NOT CHECKED", "timestamps")
    assert line and "signature not authenticated" in line[0]
    assert not lines_with(out, "PASS", "timestamps")
    assert "RESULT: INCONCLUSIVE" in out and "No timestamp with a checked signature supports" in out
    assert "not altered since" not in out, "that claim is made only where a token with a checked signature supports it"


@pytest.mark.asyncio
async def test_a_wrong_ca_certificate_fails_the_token(env, tmp_path):
    data, summary, fake = await make_bundle(env)
    other = tmp_path / "other.pem"
    other.write_text(ca_pem(make_authority("Another CA")[0]))
    work = tmp_path / "w"
    work.mkdir()
    shutil.copy(VERIFIER, work / "vigil_verify.py")
    (work / "b.zip").write_bytes(data)
    shutil.copy(other, work / "other.pem")
    result = subprocess.run([sys.executable, "-I", "vigil_verify.py", "b.zip", "--tsa-ca", "other.pem"], cwd=work, capture_output=True, text=True, timeout=120)
    assert result.returncode == 1 and ("does not verify" in result.stdout or "does not chain" in result.stdout)


# ------------------------------------------------------------------ bundles that must fail, with the reason

@pytest.mark.asyncio
async def test_an_edited_event_row_fails_the_chain_check(env, tmp_path):
    data, *_ = await make_bundle(env)

    def edit(lines):
        row = json.loads(lines[1])
        row["event"]["path"] = "/tmp/something-else.py"
        lines[1] = json.dumps(row, sort_keys=True, separators=(",", ":"))
        return lines

    code, out = run_verifier(tmp_path, forge(env, data, events=edit))
    assert code == 1
    assert lines_with(out, "FAIL", "chain") and "the event does not re-hash to its stored hash (the event was edited)" in out
    assert "row 2" in out
    # without fixing the manifest as well, the file hash fails first
    code, out = run_verifier(tmp_path, forge(env, data, events=edit, rehash=False))
    assert code == 1 and "events.jsonl was changed after the manifest was written" in out


@pytest.mark.asyncio
async def test_a_deleted_row_breaks_the_link(env, tmp_path):
    data, *_ = await make_bundle(env)
    code, out = run_verifier(tmp_path, forge(env, data, events=lambda lines: lines[:1] + lines[2:]))
    assert code == 1 and "the link to the previous row is broken (a row is missing, reordered or replaced)" in out


@pytest.mark.asyncio
async def test_reordered_rows_fail(env, tmp_path):
    data, *_ = await make_bundle(env)
    code, out = run_verifier(tmp_path, forge(env, data, events=lambda lines: [lines[1], lines[0], *lines[2:]]))
    assert code == 1 and lines_with(out, "FAIL", "chain")
    assert "link to the previous row is broken" in out or "out of order" in out


@pytest.mark.asyncio
async def test_a_truncated_range_fails_even_when_the_rest_is_consistent(env, tmp_path):
    data, *_ = await make_bundle(env)
    code, out = run_verifier(tmp_path, forge(env, data, events=lambda lines: lines[:-2]))
    assert code == 1 and "rows were removed or added" in out
    # and when the manifest is rewritten to match the shorter list, the anchor no longer binds the chain
    def shorten(manifest):
        manifest["chain"]["row_count"] = 2
        manifest["chain"]["last_event_id"] = json.loads(unpack_lines(data)[1])["event_id"]

    code, out = run_verifier(tmp_path, forge(env, data, events=lambda lines: lines[:2], proof=shorten))
    assert code == 1 or code == 2
    assert not lines_with(out, "PASS", "anchor-binds")


def unpack_lines(data):
    return unpack(data)["events.jsonl"].decode().splitlines()


@pytest.mark.asyncio
async def test_an_edited_anchor_fails(env, tmp_path):
    data, *_ = await make_bundle(env)

    def corrupt(manifest):
        manifest["anchors"][0]["anchor_json"] = manifest["anchors"][0]["anchor_json"].replace('"event_count":4', '"event_count":9')

    code, out = run_verifier(tmp_path, forge(env, data, proof=corrupt))
    assert code == 1 and "its stored hash differs from the hash of its own JSON (the anchor was edited)" in out

    def rewrite_head(manifest):
        entry = manifest["anchors"][0]
        fields = json.loads(entry["anchor_json"])
        fields["chain_head"] = "ab" * 32
        entry["anchor_json"] = anchors.canonical_json(fields)
        entry["anchor_hash"] = anchors.anchor_hash_of(entry["anchor_json"])

    code, out = run_verifier(tmp_path, forge(env, data, proof=rewrite_head))
    assert code == 1
    assert "the chain was rewritten after the anchor" in out
    assert "the token's message imprint is not this anchor's hash" in out, "the timestamp still pins the original anchor"


@pytest.mark.asyncio
async def test_an_anchor_from_another_install_fails(env, tmp_path):
    data, *_ = await make_bundle(env)

    def other_install(manifest):
        entry = manifest["anchors"][0]
        fields = json.loads(entry["anchor_json"])
        fields["install_id"] = "11111111-2222-3333-4444-555555555555"
        entry["anchor_json"] = anchors.canonical_json(fields)
        entry["anchor_hash"] = anchors.anchor_hash_of(entry["anchor_json"])

    code, out = run_verifier(tmp_path, forge(env, data, proof=other_install))
    assert code == 1 and "belongs to another install" in out


@pytest.mark.asyncio
async def test_a_token_for_a_different_anchor_fails(env, tmp_path):
    data, summary, fake = await make_bundle(env, batches=2)
    assert summary["tokens"] == 2

    def swap(manifest):
        a, b = manifest["anchors"][0], manifest["anchors"][1]
        a["tsa_token_b64"], b["tsa_token_b64"] = b["tsa_token_b64"], a["tsa_token_b64"]

    work = tmp_path / "swap"
    work.mkdir()
    (work / "ca.pem").write_text(ca_pem(fake.ca))
    shutil.copy(VERIFIER, work / "vigil_verify.py")
    (work / "b.zip").write_bytes(forge(env, data, proof=swap))
    result = subprocess.run([sys.executable, "-I", "vigil_verify.py", "b.zip", "--tsa-ca", "ca.pem"], cwd=work, capture_output=True, text=True, timeout=120)
    assert result.returncode == 1
    assert "the token's message imprint is not this anchor's hash" in result.stdout


@pytest.mark.asyncio
async def test_a_swapped_public_key_fails_even_though_the_new_signature_is_valid(env, tmp_path):
    data, *_ = await make_bundle(env)
    attacker = ed25519.Ed25519PrivateKey.generate()
    public = attacker.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def swap_key(manifest):
        manifest["public_key"] = base64.b64encode(public).decode()
        manifest["public_key_fingerprint"] = hashlib.sha256(public).hexdigest()

    code, out = run_verifier(tmp_path, forge(env, data, proof=swap_key, sign_with=attacker))
    assert code == 1
    assert lines_with(out, "PASS", "signature"), "the attacker signed with their own key"
    assert lines_with(out, "FAIL", "key") and "records a different signing key" in out


@pytest.mark.asyncio
async def test_an_edited_manifest_fails_the_signature(env, tmp_path):
    data, *_ = await make_bundle(env)

    def edit(manifest):
        manifest["period"]["end"] = "2026-12-31"

    code, out = run_verifier(tmp_path, forge(env, data, proof=edit, resign=False))
    assert code == 1 and "chain-proof.json does not match chain-proof.sig (the manifest was edited" in out


@pytest.mark.asyncio
async def test_a_file_not_in_the_manifest_and_a_manifest_hash_mismatch_fail(env, tmp_path):
    data, *_ = await make_bundle(env)
    code, out = run_verifier(tmp_path, forge(env, data, extra={"notes.txt": b"added later"}, resign=False))
    assert code == 1 and "notes.txt is in the bundle but is not listed in the manifest" in out

    def wrong_hash(manifest):
        manifest["files"]["gaps.json"] = "0" * 64

    code, out = run_verifier(tmp_path, forge(env, data, proof=wrong_hash))
    assert code == 1 and "gaps.json was changed after the manifest was written" in out

    files = unpack(data)
    files["coverage.json"] = b'{"title": "x", "lines": []}'
    code, out = run_verifier(tmp_path, repack(files))
    assert code == 1 and "coverage.json was changed after the manifest was written" in out


def test_input_that_is_not_a_bundle_exits_three(tmp_path):
    code, out = run_verifier(tmp_path, b"this is not a zip file")
    assert code == 3 and "not a readable Vigil evidence bundle" in out
    code, out = run_verifier(tmp_path, repack({"chain-proof.json": b"{}", "chain-proof.sig": b""}))
    assert code == 3


# ------------------------------------------------------------------ offline, independent, plain wording

@pytest.mark.asyncio
async def test_the_verifier_uses_no_network_even_when_sockets_are_made_to_fail(env, tmp_path):
    data, summary, fake = await make_bundle(env)
    work = tmp_path / "net"
    work.mkdir()
    shutil.copy(VERIFIER, work / "vigil_verify.py")
    (work / "b.zip").write_bytes(data)
    (work / "ca.pem").write_text(ca_pem(fake.ca))
    (work / "wrapper.py").write_text(WRAPPER_SOURCE, encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", "wrapper.py", "b.zip", "--tsa-ca", "ca.pem"], cwd=work, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "NETWORK ACCESS ATTEMPTED" not in result.stdout + result.stderr


def test_the_verifier_imports_nothing_from_the_backend_or_the_network():
    source = VERIFIER.read_text(encoding="utf-8")
    imported = set(re.findall(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", source, re.MULTILINE))
    roots = {name.split(".")[0] for name in imported}
    assert roots <= {"argparse", "base64", "hashlib", "json", "sys", "zipfile", "datetime", "cryptography"}, roots
    for forbidden in ("core", "api", "db", "backend", "socket", "http", "urllib", "httpx", "requests", "ssl"):
        assert forbidden not in roots


@pytest.mark.asyncio
async def test_the_verifier_output_and_the_spec_use_the_agreed_words(env, tmp_path):
    data, summary, fake = await make_bundle(env)
    outputs = [run_verifier(tmp_path, data)[1]]
    outputs.append(run_verifier(tmp_path, forge(env, data, events=lambda lines: lines[:1] + lines[2:]))[1])
    source = VERIFIER.read_text(encoding="utf-8")
    spec = (ROOT / "docs" / "design" / "evidence-bundle-spec.md").read_text(encoding="utf-8")
    for name, text in [("output", "\n".join(outputs)), ("verifier source", source), ("spec", spec)]:
        lowered = text.lower()
        for phrase in ("tamper", "authentic", "verified by authority", "cannot be altered", "immutable"):
            assert phrase not in lowered.replace("signature not authenticated", ""), (name, phrase)


def test_the_spec_documents_the_canonical_form_the_verifier_uses():
    spec = (ROOT / "docs" / "design" / "evidence-bundle-spec.md").read_text(encoding="utf-8")
    for needed in ("( prev_hash + canonical_string )", "id, agent_id, session_id, event_type, path, detail, file_count",
                   "`None` becomes the empty string", "joined with `|`", "000000000000000000000000000000000000000000000000000000000000000",
                   "chain-proof.json", "chain-proof.sig", "events.jsonl", "key_fingerprint", "NOT CHECKED"):
        assert needed in spec, needed
    # the spec's own example hash is reproducible with the stated rule
    from core.evidence_chain import compute_row_hash

    row = {"id": 1, "agent_id": 2, "session_id": "s", "event_type": "file_write", "path": "/p", "detail": None, "file_count": 1,
           "data_volume_bytes": 0, "severity": "low", "anomaly_score": 0.5, "pid": None, "behaviour_score": None,
           "event_source": "poll", "created_at": "2026-10-01 07:00:00"}
    expected = hashlib.sha256(("0" * 64 + "1|2|s|file_write|/p||1|0|low|0.5|||poll|2026-10-01 07:00:00").encode()).hexdigest()
    assert compute_row_hash(row, "0" * 64) == expected and expected in spec


# ------------------------------------------------------------------ the API

@pytest.mark.asyncio
async def test_the_export_endpoint_returns_a_bundle_and_reports_an_empty_range(env):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.export as export_module

    await add_anchor(env, events=3)
    app = FastAPI()
    app.include_router(export_module.router)
    client = TestClient(app)
    response = client.get("/export/bundle", params={"start": DAY, "end": DAY})
    assert response.status_code == 200 and response.headers["content-type"] == "application/zip"
    assert "vigil-evidence-" in response.headers["content-disposition"] and DAY in response.headers["content-disposition"]
    assert set(unpack(response.content)) >= {"chain-proof.json", "chain-proof.sig", "events.jsonl"}
    empty = client.get("/export/bundle", params={"start": "2020-01-01", "end": "2020-01-02"})
    assert empty.status_code == 400 and "no sealed events" in empty.json()["detail"].lower()
    assert client.get("/export/bundle", params={"start": "nope", "end": DAY}).status_code == 400
