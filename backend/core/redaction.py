"""Redacts secret-shaped values out of a command line before it is ever
stored anywhere: an event's detail.args, an alert's description/target,
or an exported report. Applied at the single place a cmdline is read
from the process snapshot cache (watchers/process_watcher.py::
_gather_spawn_info), so every downstream consumer gets the redacted
text for free.

Deterministic, regex-based, no network/DB access -- this runs on every
newly-observed process spawn, so it must stay fast and side-effect free.

Covers:
  - --password/--pass/--pwd/--token/--secret/--api-key/--apikey/--auth/
    --key style flags, both "--flag value" and "--flag=value"
  - mysql-style -p<password> (no space between flag and value -- "-p "
    with a space, e.g. a port number, is deliberately left alone)
  - Authorization header values: Bearer <token>, Basic <token>
  - URLs with embedded user:password@ credentials
  - KEY=VALUE pairs whose key name looks secret-shaped (password,
    secret, token, apikey, api_key, passwd, anywhere in the key)
  - recognizable token shapes (sk-..., ghp_..., github_pat_..., AKIA...,
    xoxb-/xoxp-...) wherever they appear in the line, since those
    prefixes are distinctive enough not to false-positive on ordinary
    text

Deliberately does NOT redact every long base64/hex-looking string
wherever it appears in a command line -- that would also eat git commit
hashes, UUIDs, and similar ordinary opaque values that aren't secrets.
A value of unknown shape is only redacted when it immediately follows a
secrets-shaped flag or '=', which the flag/KEY=VALUE rules above already
capture regardless of what the value itself looks like.
"""

import re

REDACTED = "[REDACTED]"

_SECRET_FLAG_NAMES = r"password|pass|pwd|token|secret|api-key|apikey|auth|key"
_SECRET_KEY_NAMES = r"password|secret|token|apikey|api_key|passwd"

# Excludes quote characters from a captured value -- a shell-quoted
# argument like `-H "Authorization: Bearer abc123"` must not have the
# closing quote swallowed into the redacted span.
_VALUE = r'[^\s"\']+'

_RULES: list[tuple[re.Pattern, str]] = [
    # --flag=value
    (re.compile(rf"(--(?:{_SECRET_FLAG_NAMES})=)({_VALUE})", re.IGNORECASE), rf"\1{REDACTED}"),
    # --flag value (space separated)
    (re.compile(rf"(--(?:{_SECRET_FLAG_NAMES})\s+)({_VALUE})", re.IGNORECASE), rf"\1{REDACTED}"),
    # mysql-style -p<password>, concatenated with no space. Must not be
    # preceded by another '-' (so it never fires inside "--password...",
    # which the rule above already handled) and must start at a token
    # boundary (string start or preceded by whitespace) so it only ever
    # matches a real standalone "-p" flag, not a substring mid-word.
    (re.compile(rf"(?:^|(?<=\s))(-p)({_VALUE})"), rf"\1{REDACTED}"),
    # Authorization: Bearer <token> / Basic <token>, or a bare
    # "Bearer <token>"/"Basic <token>" without the header name present
    # (e.g. inside a quoted -H argument).
    (re.compile(rf"\b(Bearer|Basic)(\s+)({_VALUE})", re.IGNORECASE), rf"\1\2{REDACTED}"),
    # scheme://user:password@host -- only the password is replaced, the
    # username (often just an identity, not a secret) is left visible.
    (re.compile(r"(://[^/\s:@]+:)([^/\s@]+)(@)"), rf"\1{REDACTED}\3"),
    # KEY=VALUE where KEY looks secret-shaped (DB_PASSWORD=..., API_TOKEN=...).
    (re.compile(rf"\b(\w*(?:{_SECRET_KEY_NAMES})\w*=)({_VALUE})", re.IGNORECASE), rf"\1{REDACTED}"),
    # Recognizable token shapes, wherever they appear in the line.
    (re.compile(r"\bsk-[A-Za-z0-9_-]{10,}"), REDACTED),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,}"), REDACTED),
]


def redact_cmdline(cmdline: str) -> str:
    """Returns `cmdline` with secret-shaped values replaced by
    "[REDACTED]" -- flag names, paths, and ordinary arguments are left
    exactly as they were. Safe on an empty string or other falsy input,
    which is returned unchanged."""
    if not cmdline:
        return cmdline
    result = cmdline
    for pattern, repl in _RULES:
        result = pattern.sub(repl, result)
    return result
