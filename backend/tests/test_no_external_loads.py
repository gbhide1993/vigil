"""Regression guard: the web interface and the tray windows must not load anything from the
internet on their own (fonts, scripts, styles, images, frames, fetches). Plain text that
merely mentions a URL, and XML namespace strings, are fine."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
TRAY_RENDERER = ["flyout.html", "flyout.css", "flyout.js", "preload.js"]

LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
KNOWN_BAD_HOSTS = (
    "fonts.googleapis.com", "fonts.gstatic.com", "unpkg.com", "cdn.jsdelivr.net", "jsdelivr.net", "cdnjs.cloudflare.com",
    "google-analytics.com", "googletagmanager.com", "cdn.tailwindcss.com", "code.jquery.com", "ajax.googleapis.com",
)
# Strings that look like URLs but are not loaded: XML namespaces, React's error-message link, the Slack placeholder text.
JS_TEXT_ALLOWED = (
    "http://www.w3.org/", "https://reactjs.org/docs/error-decoder.html", "https://react.dev/errors", "https://hooks.slack.com/services/...",
)

URL = re.compile(r"""(?:https?:)?//[A-Za-z0-9.\-\[\]:]+[^\s"'`)<>]*""")
CSS_LOADS = re.compile(r"""(?:@import\s+(?:url\()?|url\()\s*["']?\s*((?:https?:)?//[^"')\s]+)""", re.I)
HTML_LOADS = re.compile(r"""<(?:script|link|img|iframe|source|video|audio|embed|object)\b[^>]*?\b(?:src|href|data)\s*=\s*["']((?:https?:)?//[^"']+)""", re.I | re.S)
JS_LOADS = re.compile(r"""(?:fetch|import|XMLHttpRequest[^;]*?open|WebSocket|EventSource|sendBeacon|loadURL|loadFile)\s*\(\s*[`"']((?:https?|wss?):\/\/[^`"']+)""")


def _is_local(url: str) -> bool:
    host = re.sub(r"^(?:https?:|wss?:)?//", "", url).split("/")[0]
    return any(host == h or host.startswith(h + ":") for h in LOCAL_HOSTS)


def external_loads(text: str, kind: str) -> list[str]:
    """Automatically loaded external resources found in `text` (kind: css, html or js)."""
    found = []
    patterns = {"css": [CSS_LOADS], "html": [HTML_LOADS, CSS_LOADS], "js": [JS_LOADS, CSS_LOADS]}[kind]
    for pattern in patterns:
        found += [m.group(1) for m in pattern.finditer(text)]
    return [u for u in found if not _is_local(u)]


def known_bad_hosts(text: str) -> list[str]:
    return [host for host in KNOWN_BAD_HOSTS if host in text]


# ------------------------------------------------------------- the detector itself

def test_detector_flags_the_patterns_it_exists_to_catch():
    assert external_loads("@import url('https://fonts.googleapis.com/css2?family=Inter');", "css")
    assert external_loads("a{background:url(https://cdn.example.com/x.png)}", "css")
    assert external_loads('<link rel="stylesheet" href="https://cdn.jsdelivr.net/x.css">', "html")
    assert external_loads('<script src="//unpkg.com/react"></script>', "html")
    assert external_loads('fetch("https://api.example.com/x")', "js")
    assert known_bad_hosts("see https://fonts.gstatic.com/s/inter.woff2")


def test_detector_ignores_local_resources_and_plain_text():
    assert external_loads("@import url('./x.css'); a{background:url(/assets/x.png)}", "css") == []
    assert external_loads('<script type="module" src="/assets/index.js"></script>', "html") == []
    assert external_loads('fetch("http://localhost:7422/api/health"); fetch(`/api/stats`)', "js") == []
    assert external_loads('<p>See <a href="https://getvvault.com/vigil">docs</a></p>', "html") == [], "a link the user must click is fine"
    assert external_loads('const svg = "http://www.w3.org/2000/svg"', "js") == []


# ------------------------------------------------------------- the source

def _source_files():
    files = [p for p in (FRONTEND / "src").rglob("*") if p.suffix in (".css", ".jsx", ".js")]
    files.append(FRONTEND / "index.html")
    files += [ROOT / "tray" / name for name in TRAY_RENDERER if (ROOT / "tray" / name).exists()]
    return files


def test_frontend_source_and_tray_windows_load_nothing_external():
    problems = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        kind = {".css": "css", ".html": "html"}.get(path.suffix, "js")
        problems += [f"{path.relative_to(ROOT)}: {url}" for url in external_loads(text, kind)]
        problems += [f"{path.relative_to(ROOT)}: {host}" for host in known_bad_hosts(text)]
    assert problems == []


def test_fonts_are_bundled_from_npm_and_licensed():
    main = (FRONTEND / "src" / "main.jsx").read_text(encoding="utf-8")
    for family in ("inter", "jetbrains-mono"):
        assert f"@fontsource/{family}/latin-400.css" in main
    css = (FRONTEND / "src" / "index.css").read_text(encoding="utf-8")
    assert "@import" not in css
    licences = (FRONTEND / "public" / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
    assert licences.count("SIL OPEN FONT LICENSE Version 1.1") == 2, "the full licence text for each font"
    assert "Inter" in licences and "JetBrains Mono" in licences


def test_docs_say_what_the_app_contacts_over_the_network():
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Network contact" in coverage and "By default: nothing" in coverage and "webhook URL" in coverage
    assert "What Vigil contacts over the network" in readme and "Nothing, by default" in readme


# ------------------------------------------------------------- the built interface

DIST = FRONTEND / "dist"


@pytest.mark.skipif(not (DIST / "index.html").exists(), reason="frontend/dist is not built (run npm run build in frontend/)")
def test_built_interface_loads_nothing_external():
    problems = []
    assets = list((DIST / "assets").glob("*"))
    for path in [DIST / "index.html", *assets]:
        if path.suffix in (".woff", ".woff2", ".png", ".ico"):
            continue
        text = path.read_text(encoding="utf-8")
        kind = {".css": "css", ".html": "html"}.get(path.suffix, "js")
        problems += [f"{path.name}: {url}" for url in external_loads(text, kind)]
        problems += [f"{path.name}: {host}" for host in known_bad_hosts(text)]
        if kind == "js":
            for url in URL.findall(text):
                if url.startswith(("http:", "https:")) and not _is_local(url) and not url.startswith(JS_TEXT_ALLOWED):
                    problems.append(f"{path.name}: unexpected URL string {url[:80]}")
    assert problems == []


@pytest.mark.skipif(not (DIST / "index.html").exists(), reason="frontend/dist is not built (run npm run build in frontend/)")
def test_built_interface_carries_its_own_fonts_and_licence():
    names = [p.name for p in (DIST / "assets").glob("*.woff2")]
    for family in ("inter-latin-400", "inter-latin-700", "jetbrains-mono-latin-400", "jetbrains-mono-latin-700"):
        assert any(n.startswith(family) for n in names), family
    css = "".join(p.read_text(encoding="utf-8") for p in (DIST / "assets").glob("*.css"))
    assert "font-family:Inter" in css.replace("'", "").replace('"', "").replace(" ", "") or "font-family:\"Inter\"" in css
    assert "url(/assets/" in css or "url(./" in css or "url(data:" in css
    assert (DIST / "THIRD_PARTY_LICENSES.md").exists()
