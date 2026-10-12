"""Source-level checks of the History search, sidebar wording, date picker and
table CSS. The rendered result was checked in a real browser separately; these
tests keep the behaviour from regressing silently."""

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "frontend" / "src"


def _read(*parts):
    return (SRC.joinpath(*parts)).read_text(encoding="utf-8")


def _node(script):
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=str(ROOT), capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_session_id_and_plain_text_go_to_the_server_while_question_style_queries_stay_local():
    out = _node("""
    import { isIntentQuery } from './frontend/src/queryParser.js'
    const qs = ['d94550d7', 'D94550D7', 'd', 'd94550d7-4b1e-4c33-9a10-0d9b1f4c7a21', 'curl', 'file12.py', 'claude', '.env',
                'after 6pm', 'yesterday', 'today', 'credentials', 'modified auth', 'spawned', 'connected to api.x.com', 'mcp', 'monday']
    console.log(JSON.stringify(Object.fromEntries(qs.map((q) => [q, isIntentQuery(q)]))))
    """)
    for q in ("d94550d7", "D94550D7", "d", "d94550d7-4b1e-4c33-9a10-0d9b1f4c7a21", "curl", "file12.py", "claude", ".env"):
        assert out[q] is False, q
    for q in ("after 6pm", "yesterday", "today", "credentials", "modified auth", "spawned", "connected to api.x.com", "mcp", "monday"):
        assert out[q] is True, q


def test_history_search_is_live_cancellable_and_server_side():
    history = _read("components", "History.jsx")
    assert "api.searchEvents(" in history
    assert "new AbortController()" in history and "controller.abort()" in history
    assert re.search(r"SEARCH_DEBOUNCE_MS = (1[5-9]\d|2[0-4]\d|250)\b", history), "debounce between 150 and 250 ms"
    assert "onKeyDown={(e) => e.key === 'Escape'" in history and "Enter" not in history
    assert 'aria-label="Clear search"' in history and "query-result-count" in history
    # the old behaviour: filter only the 50 latest loaded events
    assert "parseQuery(query, events)" not in history
    assert "api.sessionReportUrl(singleSession.session_id)" in history, "one matching session exports that session"
    api = _read("api.js")
    assert "searchEvents:" in api and "sessionReportUrl:" in api and "callerSignal" in api


def test_sidebar_separates_recognised_from_running_and_describes_approval():
    sidebar = _read("components", "Sidebar.jsx")
    assert "Watching now" not in sidebar and "awaiting approval" not in sidebar
    assert "Recognised agents" in sidebar and "active now" in sidebar and "not approved yet" in sidebar
    # the dot reflects activity, never approval
    dot = sidebar[sidebar.index("function statusDotColor"):sidebar.index("function approvalLabel")]
    assert "approved === 0" not in dot and "current_status === 'active'" in dot


def test_dashboard_card_is_labelled_for_what_it_counts():
    history = _read("components", "History.jsx")
    assert 'label="Approved Agents"' in history and 'label="Active Agents"' not in history


def test_export_uses_a_calendar_input_with_quick_choices_and_local_day_note():
    export = _read("components", "Export.jsx")
    field = _read("components", "DateField.jsx")
    assert 'placeholder="today or YYYY-MM-DD"' not in export and "<DateField" in export
    assert 'type="date"' in field and "Yesterday" in field and "Today" in field
    assert "local day" in field and "timezoneLabel" in field and "in the future" in field


def test_no_new_frontend_dependencies():
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    # fonts only: bundled, open licence, no runtime fetch (see test_no_external_loads.py)
    assert set(package["dependencies"]) == {"react", "react-dom", "@fontsource/inter", "@fontsource/jetbrains-mono"}
    assert set(package["devDependencies"]) == {"@vitejs/plugin-react", "vite"}


def test_css_lets_long_values_wrap_instead_of_widening_the_page():
    css = (SRC / "index.css").read_text(encoding="utf-8")
    row = css[css.index(".feed-row {"):css.index("}", css.index(".feed-row {"))]
    assert "minmax(0, 1fr)" in row and "108px" in row
    for selector in (".incident-title", ".alert-card-v2-title", ".alert-detail-text", ".story-target", ".cell-wrap"):
        assert selector in css
    assert "overflow-wrap: anywhere" in css and ".copy-btn" in css
