from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import unquote

REDACTED = "[REDACTED]"

SECRET_NAME = re.compile(
    r"(?i)(token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth|credential|"
    r"private[_-]?key|access[_-]?key|bearer|cookie|session|signature|^key$|^pass$)"
)

SECRET_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-ant-[A-Za-z0-9_-]{16,}"
    r"|sk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")"
)

_ASSIGNMENT = re.compile(
    r"^(?P<prefix>-{0,2}|/)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>[=:])(?P<value>.*)$"
)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"<>`]+", re.IGNORECASE)
_AUTH_SCHEME = re.compile(r"(?i)\b(?P<scheme>bearer|basic)(?P<space>\s+)[A-Za-z0-9._~+/=-]{6,}")
_INLINE_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|"
    r"credential|private[_-]?key|access[_-]?key|cookie|session|signature)[A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*[=:]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s'\"&;|,)}]+)"
)


def is_secret_name(name: str) -> bool:
    return SECRET_NAME.search(name) is not None


def redact_text(value: str) -> str:
    return SECRET_VALUE.sub(REDACTED, value)


def redact_free_text(value: str) -> str:
    value = _URL.sub(lambda m: redact_url(m.group(0)), value)
    value = _AUTH_SCHEME.sub(lambda m: f"{m['scheme']}{m['space']}{REDACTED}", value)
    value = _INLINE_ASSIGNMENT.sub(lambda m: f"{m['name']}{m['sep']}{REDACTED}", value)
    return redact_text(value)


def redact_url(url: str) -> str:
    scheme, sep, rest = url.partition("://")
    if not sep:
        return redact_text(url)
    authority_end = len(rest)
    for marker in ("/", "?", "#"):
        index = rest.find(marker)
        if index != -1:
            authority_end = min(authority_end, index)
    authority, tail = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    path, qmark, query_and_fragment = tail.partition("?")
    if not qmark:
        return f"{scheme}://{authority}{redact_text(path)}"
    query, hash_mark, fragment = query_and_fragment.partition("#")
    pieces = []
    for piece in query.split("&"):
        key, eq, _ = piece.partition("=")
        if eq and is_secret_name(unquote(key)):
            pieces.append(f"{key}={REDACTED}")
        else:
            pieces.append(redact_text(piece))
    rebuilt = f"{scheme}://{authority}{redact_text(path)}?{'&'.join(pieces)}"
    if hash_mark:
        rebuilt += "#" + redact_text(fragment)
    return rebuilt


def redact_args(args: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    redact_next = False
    for arg in args:
        if redact_next and not arg.startswith("-"):
            result.append(REDACTED)
            redact_next = False
            continue
        redact_next = False
        match = _ASSIGNMENT.match(arg)
        if match and is_secret_name(match["name"]):
            result.append(f"{match['prefix']}{match['name']}{match['sep']}{REDACTED}")
            continue
        if match is None and arg.startswith("-") and is_secret_name(arg.lstrip("-")):
            result.append(arg)
            redact_next = True
            continue
        result.append(redact_free_text(arg))
    return tuple(result)
