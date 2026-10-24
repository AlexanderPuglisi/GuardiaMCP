from __future__ import annotations

import re
from collections.abc import Sequence
from itertools import pairwise
from urllib.parse import unquote

REDACTED = "[REDACTED]"

NO_SECRET, WEAK_SECRET, STRONG_SECRET = 0, 1, 2
STRONG_WORDS = frozenset(
    {
        "token",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passwd",
        "pwd",
        "passphrase",
        "apikey",
        "apikeys",
        "credential",
        "credentials",
        "bearer",
        "authorization",
        "privatekey",
        "accesskey",
        "secretkey",
    }
)
STRONG_ENDINGS = ("token", "secret", "password", "passwd", "apikey", "passphrase")
STRONG_PAIRS = frozenset({("api", "key"), ("api", "keys"), ("private", "key"), ("access", "key")})
WEAK_WORDS = frozenset({"auth", "session", "cookie", "cookies", "signature"})
PUBLIC_WORDS = frozenset({"public", "publishable", "pub"})
DESCRIPTOR_WORDS = frozenset(
    {
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "dir",
        "dirs",
        "directory",
        "folder",
        "location",
        "uri",
        "url",
        "urls",
        "endpoint",
        "host",
        "hostname",
        "domain",
        "email",
        "name",
        "id",
        "ids",
        "mode",
        "env",
        "var",
        "variable",
        "type",
        "kind",
        "method",
        "scope",
        "scopes",
        "provider",
        "enabled",
        "disabled",
        "required",
        "timeout",
        "ttl",
        "expiry",
        "expires",
        "expiration",
        "length",
        "size",
        "count",
        "limit",
        "format",
        "version",
        "region",
        "port",
        "prefix",
        "suffix",
        "store",
        "storage",
        "cache",
        "level",
        "strategy",
        "issuer",
        "audience",
    }
)
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_NAME_SEPARATORS = re.compile(r"[^a-z0-9]+")

SECRET_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-ant-[A-Za-z0-9_-]{16,}"
    r"|sk-(?!ecdsa-|ssh-)(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")"
)
REFERENCE = re.compile(
    r"\$\{[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%|^\$[A-Za-z_][A-Za-z0-9_]*$|\$env:[A-Za-z_]"
    r"|(?<![A-Za-z0-9$])\$[A-Z_][A-Z0-9_]+\b"
)

_ASSIGNMENT = re.compile(
    r"^(?P<prefix>-{0,2}|/)(?P<name>[A-Za-z0-9_.-]+)(?P<sep>[=:])(?P<value>.*)$"
)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s'\"<>`]+", re.IGNORECASE)
AUTH_SCHEME = re.compile(r"(?i)\b(?P<scheme>bearer|basic)(?P<space>\s+)[A-Za-z0-9._~+/=-]{6,}")
_INLINE_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|"
    r"credential|private[_-]?key|access[_-]?key|cookie|session|signature)[A-Za-z0-9_.-]*)"
    r"(?P<sep>\s*[=:]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s'\"&;|,)}]+)"
)
_LOCAL_PATH = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\|~[\\/]|\.{1,2}[\\/]|%[A-Za-z_]\w*%[\\/]|\$\{?[A-Za-z_]\w*\}?[\\/])"
)
_POSIX_PATH = re.compile(
    r"^/(?:home|users|etc|var|opt|usr|tmp|mnt|root|srv|run|data|workspace|app|private|volumes"
    r"|library)(?:/|$)"
    r"|^/\S*\.(?:json|ya?ml|toml|pem|key|crt|cer|p12|pfx|txt|env|ini|cfg|conf|db|sqlite)$",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"^[^@\s:/]+@[^@\s:/]+\.[A-Za-z]{2,}$")
_VARIABLE_NAME = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_URL_START = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_RANDOM_SEGMENTS = re.compile(r"[-_.:/+=]+")


def name_tokens(name: str) -> tuple[str, ...]:
    spaced = _CAMEL_BOUNDARY.sub("_", name).lower()
    return tuple(token for token in _NAME_SEPARATORS.split(spaced) if token)


def secret_name_strength(name: str) -> int:
    tokens = name_tokens(name)
    if not tokens or tokens[-1] in DESCRIPTOR_WORDS or PUBLIC_WORDS.intersection(tokens):
        return NO_SECRET
    strong = (
        tokens in (("key",), ("pass",))
        or tokens[-1] == "pass"
        or any(token in STRONG_WORDS or token.endswith(STRONG_ENDINGS) for token in tokens)
        or any(pair in STRONG_PAIRS for pair in pairwise(tokens))
    )
    if strong:
        return STRONG_SECRET
    if WEAK_WORDS.intersection(tokens) or tokens[-1] == "key":
        return WEAK_SECRET
    return NO_SECRET


def is_secret_name(name: str) -> bool:
    return secret_name_strength(name) != NO_SECRET


def is_plain_value(value: str) -> bool:
    text = value.strip().strip("\"'")
    return any(
        pattern.match(text) is not None
        for pattern in (_LOCAL_PATH, _POSIX_PATH, _EMAIL, _VARIABLE_NAME, _URL_START)
    )


def looks_random(value: str) -> bool:
    text = value.strip()
    if len(text) < 8 or any(char.isspace() for char in text):
        return False
    return any(
        len(part) >= 24
        or (
            len(part) >= 8
            and any(char.isdigit() for char in part)
            and any(char.isalpha() for char in part)
        )
        for part in _RANDOM_SEGMENTS.split(text)
    )


def is_secret_assignment(name: str, value: str) -> bool:
    strength = secret_name_strength(name)
    text = value.strip().strip("\"'")
    if strength == NO_SECRET or not text or REFERENCE.search(text) or is_plain_value(text):
        return False
    return strength == STRONG_SECRET or looks_random(text)


def redact_text(value: str) -> str:
    return SECRET_VALUE.sub(REDACTED, value)


def _redact_inline(match: re.Match[str]) -> str:
    if not is_secret_assignment(match["name"], match["value"]):
        return match.group(0)
    return f"{match['name']}{match['sep']}{REDACTED}"


def redact_free_text(value: str) -> str:
    value = _URL.sub(lambda m: redact_url(m.group(0)), value)
    value = AUTH_SCHEME.sub(lambda m: f"{m['scheme']}{m['space']}{REDACTED}", value)
    value = _INLINE_ASSIGNMENT.sub(_redact_inline, value)
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
        key, eq, value = piece.partition("=")
        if eq and is_secret_assignment(unquote(key), unquote(value)):
            pieces.append(f"{key}={REDACTED}")
        else:
            pieces.append(redact_text(piece))
    rebuilt = f"{scheme}://{authority}{redact_text(path)}?{'&'.join(pieces)}"
    if hash_mark:
        rebuilt += "#" + redact_text(fragment)
    return rebuilt


def redact_args(args: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    pending: str | None = None
    for arg in args:
        if pending is not None and not arg.startswith("-"):
            result.append(REDACTED if is_secret_assignment(pending, arg) else redact_free_text(arg))
            pending = None
            continue
        pending = None
        match = _ASSIGNMENT.match(arg)
        if match and is_secret_assignment(match["name"], match["value"]):
            result.append(f"{match['prefix']}{match['name']}{match['sep']}{REDACTED}")
            continue
        if match is None and arg.startswith("-") and is_secret_name(arg.lstrip("-")):
            result.append(arg)
            pending = arg.lstrip("-")
            continue
        result.append(redact_free_text(arg))
    return tuple(result)
