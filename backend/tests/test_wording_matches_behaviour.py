"""User-facing text must not claim more than the code does: Red Line titles say what the rule can see,
the READMEs and the coverage page agree with it, and no document claims a protection Vigil does not give.
No rule logic is tested here; only the words."""

import ast
import re
import time
from pathlib import Path

import pytest

import core.red_lines as red_lines
from core import report_coverage

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"

# Rules that need a file-read event. Vigil records none on Windows, so they cannot fire; their text says so.
READ_RULES = {"env_outside_workspace", "cross_project_read"}
READ_WORDS = re.compile(r"\b(accessed|read|opened)\b", re.IGNORECASE)
FORBIDDEN = ("tamper", "cannot be altered", "cannot be changed", "immutable")


def _literal_text(node) -> str:
    """The literal parts of a string or f-string expression (implicit concatenation included)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value for part in node.values if isinstance(part, ast.Constant))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _literal_text(node.left) + _literal_text(node.right)
    return ""


def _fire_calls(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_fire":
            rule_key = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None
            keywords = {k.arg: k.value for k in node.keywords}
            yield rule_key, _literal_text(keywords["title"]), _literal_text(keywords["description"])


def test_every_red_line_title_and_description_matches_what_the_rule_can_see():
    seen = {}
    for rule_key, title, description in _fire_calls(BACKEND / "core" / "red_lines.py"):
        seen[rule_key] = (title, description)
        text = f"{title} {description}"
        if rule_key in READ_RULES:
            assert "requires file-read events" in title and "not recorded on Windows in this version" in title, rule_key
            assert "requires file-read events" in description and "does not record on Windows in this version" in description, rule_key
        else:
            assert not READ_WORDS.search(text), f"{rule_key} says accessed, read or opened but only sees changes: {text}"
    # every rule is still in the code
    assert set(seen) >= {
        "ssh_access", "env_outside_workspace", "claude_cache_write", "unknown_destination", "dangerous_command",
        "cross_project_read", "env_redirect", "config_exec", "mcp_autoapproval",
    }


def test_the_ssh_rule_says_changed_and_that_reading_is_not_detected():
    titles = {key: (title, description) for key, title, description in _fire_calls(BACKEND / "core" / "red_lines.py")}
    title, description = titles["ssh_access"]
    assert title == "RED LINE: SSH directory changed by "
    assert "created, changed, moved or deleted a file in your SSH directory" in description
    assert "Reads are not recorded, so reading a key is not detected" in description


def test_the_batch_summary_uses_the_rule_names_not_access():
    class Capture:
        def __init__(self):
            self.descriptions = []

        async def fire_alert(self, agent_id, severity, title, description, **kwargs):
            self.descriptions.append(description)

    import asyncio

    rules = red_lines.RedLines()
    rules.alerter = Capture()
    rules._state[(1, "ssh_access", "t")] = {"last_fired": time.time() - 10_000, "batched": 3}
    rules._state[(1, "env_outside_workspace", "t")] = {"last_fired": time.time() - 10_000, "batched": 2}
    rules._state[(1, "claude_cache_write", "t")] = {"last_fired": time.time() - 10_000, "batched": 1}

    async def run():
        for key in ("ssh_access", "env_outside_workspace", "claude_cache_write"):
            await rules._fire(1, key, "high", title="t", description="d", extra_detail={}, target="t")

    asyncio.run(run())
    ssh, env, cache = rules.alerter.descriptions
    assert "(3 more SSH directory change events in the last 5 min)" in ssh
    assert "(2 more environment file read outside the workspace (needs file-read events) events" in env
    assert "(1 more claude cache write events" in cache
    assert "ssh access" not in ssh.lower()


def test_the_policy_alerts_for_credential_and_out_of_scope_paths_say_changed():
    alerter_source = (BACKEND / "core" / "alerter.py").read_text(encoding="utf-8")
    for old in ("Credential path accessed", "Agent accessed", "Out-of-scope directory access"):
        assert old not in alerter_source, old
    assert 'title=f"Credential path changed: {path}"' in alerter_source
    assert "Reads are not recorded, so reading one is not detected" in alerter_source
    assert 'title=f"Out-of-scope directory change: {path}"' in alerter_source
    story = (ROOT / "frontend" / "src" / "components" / "IncidentList.jsx").read_text(encoding="utf-8")
    assert "'changed credential file'" in story and "'accessed credential file'" not in story


# ------------------------------------------------------------------ the documents

READMES = ["README.md", "vigil-plugin/README.md", "vigil-vscode/README.md"]


@pytest.mark.parametrize("name", READMES)
def test_readmes_make_no_protection_claims_vigil_does_not_back(name):
    text = (ROOT / name).read_text(encoding="utf-8").lower()
    for word in FORBIDDEN:
        assert word not in text, (name, word)


def test_the_report_coverage_block_and_the_coverage_page_make_no_such_claims():
    block = " ".join([report_coverage.TITLE, *report_coverage.LINES]).lower()
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8").lower()
    for word in FORBIDDEN:
        assert word not in block, word
        assert word not in coverage, word


def test_no_readme_says_reads_are_caught_and_all_state_the_read_limit():
    for name in READMES:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "reads are not recorded" in text.lower() or "file reads are not recorded" in text.lower(), name
        assert not re.search(r"(detects?|catches|flags|monitors?) (file )?reads", text, re.IGNORECASE), name


def test_the_red_line_lists_match_what_the_rules_can_see():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    vscode = (ROOT / "vigil-vscode" / "README.md").read_text(encoding="utf-8")
    plugin = (ROOT / "vigil-plugin" / "README.md").read_text(encoding="utf-8")
    for text in (readme, vscode):
        assert "created, changed, moved or deleted" in text and "SSH directory changed" in text
        assert "reading a key is not detected" in text
    assert "need file-read events, which are not recorded on Windows in this version, so they cannot fire" in readme
    assert "two need file-read events, which are not recorded on Windows" in vscode
    assert "changes to credential files" in plugin and "reading a credential file is not detected" in plugin
    assert "credential-file activity" not in plugin


def test_the_coverage_page_matches_and_states_the_session_limit():
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert "Session durations and counts can be off: sessions close lazily because the scheduled idle sweep is off." in coverage
    assert "The alert title is \"SSH directory changed\"" in coverage
    assert coverage.count("requires file-read events, which are not recorded on Windows in this version") >= 2
    assert "Rule titles for RL1 use \"accessed\"" not in coverage


def test_the_licence_comments_say_30_days_and_that_the_limits_are_not_enforced():
    source = (BACKEND / "license" / "license_service.py").read_text(encoding="utf-8")
    main = (BACKEND / "main.py").read_text(encoding="utf-8")
    assert "14-day" not in source and "14-day" not in main.split("import asyncio")[0]
    assert "30-day trial" in source and "30-day trial" in main
    assert "not enforced anywhere" in source
    from license import license_service

    assert license_service.TRIAL_DAYS == 30 and license_service.TRIAL_AGENT_LIMIT == 1 and license_service.TRIAL_RETENTION_HOURS == 24


def test_the_extension_package_text_makes_no_such_claims():
    for name in ("vigil-vscode/package.json", "vigil-vscode/CHANGELOG.md"):
        text = (ROOT / name).read_text(encoding="utf-8").lower()
        for word in FORBIDDEN:
            assert word not in text, (name, word)


# ------------------------------------------------------------------ "read 0" in summaries and cards

def test_new_session_summaries_never_show_a_read_count():
    from core.digest import generate_summary

    for writes, expected in ((0, None), (1, "wrote 1 file (file reads are not recorded)"), (7, "wrote 7 files (file reads are not recorded)")):
        text = generate_summary("claude", {"file_reads": 0, "file_writes": writes, "proc_spawns": 2, "alert_count": 0})
        assert not re.search(r"\bread \d", text), text
        if expected:
            assert expected in text
    quiet = generate_summary("claude", {"file_reads": 0, "file_writes": 0})
    assert "read" not in quiet.lower().replace("already", "")


def test_the_incidents_card_states_writes_and_that_reads_are_not_recorded():
    card = (ROOT / "frontend" / "src" / "components" / "SessionInsightCard.jsx").read_text(encoding="utf-8")
    assert "file reads are not recorded" in card
    assert "fileReads" not in card and "> read{" not in card and " read{' '}" not in card


# ------------------------------------------------------------------ old stored summaries, display-time only

LEGACY = "claude read 0 and wrote 7 files; spawned 2 processes this session."
LEGACY_ONE = "claude read 0 and wrote 1 file this session."
NEW = "claude wrote 7 files (file reads are not recorded); spawned 2 processes this session."


def test_display_summary_rewrites_only_a_zero_read_count():
    from core.digest import display_summary

    assert display_summary(LEGACY) == NEW
    assert display_summary(LEGACY_ONE) == "claude wrote 1 file (file reads are not recorded) this session."
    assert display_summary(NEW) == NEW
    assert display_summary("claude read 12 and wrote 7 files this session.") == "claude read 12 and wrote 7 files this session."
    assert display_summary("claude read 10 and wrote 7 files this session.") == "claude read 10 and wrote 7 files this session."
    assert display_summary(None) is None and display_summary("") == ""


@pytest.mark.asyncio
async def test_both_endpoints_rewrite_the_legacy_summary_and_leave_the_stored_row_alone(tmp_path, monkeypatch):
    import uuid

    import db.database as database
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.alerts as alerts_module
    import api.sessions as sessions_module

    monkeypatch.setattr("config.policy.POLICY_FILE", tmp_path / "no-such-policy.json")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    database._db = None
    db = await database.get_db()
    try:
        cur = await db.execute("INSERT INTO agents (name, process_name, approved) VALUES (?, 'x', 1)", (f"disp_{uuid.uuid4().hex[:8]}",))
        agent_id = cur.lastrowid
        legacy_id, new_id = str(uuid.uuid4()), str(uuid.uuid4())
        for sid, text in ((legacy_id, LEGACY), (new_id, NEW)):
            await db.execute(
                "INSERT INTO sessions (id, agent_id, started_at, ended_at, summary) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)",
                (sid, agent_id, text),
            )
            await db.execute(
                "INSERT INTO alerts (agent_id, severity, title, description, rule_type, session_id) VALUES (?, 'low', ?, 'd', 'x', ?)",
                (agent_id, f"t-{sid}", sid),
            )
        await db.commit()

        app = FastAPI()
        app.include_router(alerts_module.router)
        app.include_router(sessions_module.router)
        client = TestClient(app)
        try:
            sessions = {s["id"]: s["summary"] for s in client.get("/sessions").json()["sessions"]}
            alerts = {a["session_id"]: a["session_summary"] for a in client.get("/alerts", params={"limit": 500}).json()["alerts"]}
            assert sessions[legacy_id] == NEW and sessions[new_id] == NEW
            assert alerts[legacy_id] == NEW and alerts[new_id] == NEW

            cur = await db.execute("SELECT summary FROM sessions WHERE id = ?", (legacy_id,))
            assert (await cur.fetchone())["summary"] == LEGACY, "the stored row must not be modified"
        finally:
            await db.execute("DELETE FROM alerts WHERE session_id IN (?, ?)", (legacy_id, new_id))
            await db.execute("DELETE FROM sessions WHERE id IN (?, ?)", (legacy_id, new_id))
            await db.commit()
    finally:
        await database.close_db()
