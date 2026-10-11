"""Recognises the shell wrapper Claude Code puts around every Bash tool
command, and pulls out the command the agent actually asked to run.

Claude Code starts each Bash command as one process whose command line is:

    <git>\\bash.exe -c source <home>/.claude/shell-snapshots/snapshot-bash-<id>.sh
        2>/dev/null || true && export TEMP='...' TMP='...' && shopt -u extglob
        2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset
        -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '<the real command,
        shell-quoted>' < /dev/null && pwd -P >| <temp file>

Matching dangerous-command rules against that whole string is wrong in two
ways: the boilerplate carries flag-like text (`unset -f`, the random id in
the snapshot file name) that combines with a word in the real command to
satisfy multi-part rules such as "rm with -r and -f", and an alert then
shows the whole wrapper rather than the command. The wrapper is NOT
suppressed: the real command is extracted (the quoting undone) and the
rules run on that command only, so `eval 'rm -rf ~'` still fires normally.

If the real command cannot be parsed (for example an unterminated quote),
only the portion after the recognised boilerplate is returned, never the
whole string: the boilerplate must not be able to match a rule, and a
dangerous command in the remainder is still caught because the remainder is
kept as raw text.
"""

import re
from dataclasses import dataclass

# "-c source <...>/shell-snapshots/snapshot-bash-<id>.sh", the unmistakable
# start of the wrapper. Matching the snapshot directory and file name (not
# just "source") keeps an ordinary `bash -c "source ./env.sh && ..."` from
# being treated as a wrapper.
_WRAPPER_START = re.compile(
    r"""(?:^|\s)-c\s+["']?source\s+\S*shell-snapshots[\\/]snapshot-[\w.-]*\.sh["']?""",
    re.IGNORECASE,
)

# Boilerplate steps stripped, in any order and repetition, from the start of
# what follows the `source` clause. Each is anchored and consumes leading
# whitespace. Anything not recognised stops the stripping and is treated as
# the start of the real command.
_REDIRECT = r"(?:\d?>\|?\s*/dev/null|2>&1|&>\s*/dev/null)"
_BOILERPLATE_STEPS = [
    re.compile(rf"\s*{_REDIRECT}(?:\s+{_REDIRECT})*"),
    re.compile(r"\s*\|\|\s*true\b"),
    re.compile(r"\s*&&"),
    re.compile(r"""\s*export\s+(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|[^\s&;|]+)\s*)+"""),
    re.compile(r"\s*shopt\s+-[su]\s+\w+"),
    # { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; }
    re.compile(r"\s*\{\s*(?:\\?builtin\s+un(?:alias|set)\b[^{};]*;\s*)+\}"),
]

# What Claude Code appends after the command: stdin from /dev/null, then a
# `pwd -P` redirected into a temp file it reads the new cwd back from.
_TRAILER = re.compile(r"\s*(?:<\s*/dev/null)?\s*(?:&&\s*pwd\s+-P\s*>\|?\s*\S+)?\s*$")
_EVAL_PREFIX = re.compile(r"eval\s+", re.IGNORECASE)


@dataclass
class Unwrapped:
    inner: str          # the command to evaluate against the rules
    parsed: bool        # True if it came from a clean `eval '<word>'` parse


class _ShellParseError(ValueError):
    pass


def _read_shell_word(s: str, i: int) -> tuple[str, int]:
    """Reads one shell word starting at s[i], undoing single quotes, double
    quotes and backslash escapes (so `'"'"'` becomes a single quote).
    Stops at unquoted whitespace or a shell operator. Raises on an
    unterminated quote."""
    out: list[str] = []
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "'":
            j = s.find("'", i + 1)
            if j == -1:
                raise _ShellParseError("unterminated single quote")
            out.append(s[i + 1:j])
            i = j + 1
        elif ch == '"':
            i += 1
            while True:
                if i >= n:
                    raise _ShellParseError("unterminated double quote")
                ch = s[i]
                if ch == '"':
                    i += 1
                    break
                if ch == "\\" and i + 1 < n and s[i + 1] in '\\"$`\n':
                    out.append(s[i + 1])
                    i += 2
                    continue
                out.append(ch)
                i += 1
        elif ch == "\\":
            if i + 1 >= n:
                raise _ShellParseError("dangling backslash")
            out.append(s[i + 1])
            i += 2
        elif ch.isspace() or ch in "<>|&;()":
            break
        else:
            out.append(ch)
            i += 1
    return "".join(out), i


def _strip_boilerplate(rest: str) -> str:
    changed = True
    while changed:
        changed = False
        for step in _BOILERPLATE_STEPS:
            m = step.match(rest)
            if m and m.end() > 0:
                rest = rest[m.end():]
                changed = True
    return rest.lstrip()


def unwrap_agent_command(cmdline: str) -> Unwrapped | None:
    """None if cmdline is not Claude Code's Bash wrapper (evaluate it as is).
    Otherwise the command the agent asked to run (never the boilerplate)."""
    if not cmdline:
        return None
    m = _WRAPPER_START.search(cmdline)
    if m is None:
        return None

    tail = _strip_boilerplate(cmdline[m.end():])

    ev = _EVAL_PREFIX.match(tail)
    if ev is not None:
        try:
            word, _end = _read_shell_word(tail, ev.end())
            return Unwrapped(inner=word.strip(), parsed=True)
        except _ShellParseError:
            # Unparseable eval argument: fall back to the raw remainder after
            # the boilerplate (still without the boilerplate and the
            # trailing pwd -P redirect), never the whole string.
            remainder = _TRAILER.sub("", tail[ev.end():])
            return Unwrapped(inner=remainder.strip(), parsed=False)

    # No eval (a wrapper variant that runs the command directly): everything
    # after the boilerplate is the command.
    return Unwrapped(inner=_TRAILER.sub("", tail).strip(), parsed=False)
