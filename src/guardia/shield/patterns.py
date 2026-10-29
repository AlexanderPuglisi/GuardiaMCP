from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from guardia.shield.windows import long_path

MAX_LEAVES = 10_000
MAX_WALK_DEPTH = 64
MAX_TEXT = 100_000
MAX_PATH_TEXT = 4096
URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s\"'<>`]+", re.IGNORECASE)
HOME_TOKENS = re.compile(
    r"^(?:~|%userprofile%|%home%|\$home|\$\{home\}|\$env:userprofile)(?=$|[\\/])", re.IGNORECASE
)
DRIVE_URL_PATH = re.compile(r"^/[a-zA-Z]:/")
DEVICE_PREFIX = re.compile(r"^//[?.]/(unc/)?", re.IGNORECASE)
LOCAL_SHARE = re.compile(r"^//(?:localhost|127\.0\.0\.1|\.)/([a-z])\$(?=/|$)", re.IGNORECASE)
DRIVE = re.compile(r"^[a-z]:$", re.IGNORECASE)
DRIVE_PATH = re.compile(r"^[a-z]:/", re.IGNORECASE)
SHORT_NAME = re.compile(r"~\d")


@dataclass(frozen=True, slots=True)
class Leaf:
    keys: tuple[str, ...]
    text: str


def leaves(value: Any, *, include_keys: bool = False) -> list[Leaf]:
    found: list[Leaf] = []
    stack: list[tuple[Any, tuple[str, ...], int]] = [(value, (), 0)]
    while stack and len(found) < MAX_LEAVES:
        current, keys, depth = stack.pop()
        if isinstance(current, str):
            found.append(Leaf(keys, current[:MAX_TEXT]))
        elif depth < MAX_WALK_DEPTH and isinstance(current, dict):
            for key, item in current.items():
                label = str(key)
                stack.append((item, (*keys, label), depth + 1))
                if include_keys:
                    stack.append((label, (*keys, label), depth + 1))
        elif depth < MAX_WALK_DEPTH and isinstance(current, list):
            stack.extend((item, keys, depth + 1) for item in current)
    return found


def _translate(pattern: str, *, separator: str | None) -> str:
    result: list[str] = []
    index = 0
    any_char = "." if separator is None else f"[^{re.escape(separator)}]"
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index) and separator is not None:
            result.append(f"(?:.*{re.escape(separator)})?")
            index += 3
        elif pattern.startswith("/**", index) and index + 3 == len(pattern) and separator:
            result.append(f"(?:{re.escape(separator)}.*)?")
            index += 3
        elif pattern.startswith("**", index):
            result.append(".*")
            index += 2
        elif char == "*":
            result.append(f"{any_char}*")
            index += 1
        elif char == "?":
            result.append(any_char)
            index += 1
        else:
            result.append(re.escape(char))
            index += 1
    return "".join(result)


def name_glob(pattern: str) -> re.Pattern[str]:
    return re.compile(_translate(pattern, separator=None), re.IGNORECASE | re.DOTALL)


def _windows_part(index: int, part: str) -> str:
    if part in ("", ".", "..") or (index == 0 and DRIVE.match(part)):
        return part
    stream = part.split(":", 1)[0]
    return stream.rstrip(" .") or stream


def _windows_path(text: str) -> str:
    device = DEVICE_PREFIX.match(text)
    if device:
        text = ("//" if device.group(1) else "") + text[device.end() :]
    text = LOCAL_SHARE.sub(lambda match: match.group(1) + ":", text, count=1)
    prefix = "//" if text.startswith("//") else ""
    parts = text[len(prefix) :].split("/")
    return prefix + "/".join(_windows_part(index, part) for index, part in enumerate(parts))


def expand_short_names(path: str) -> str:
    if not DRIVE_PATH.match(path) or not SHORT_NAME.search(path):
        return path
    parts = path.split("/")
    for end in range(len(parts), 1, -1):
        if not SHORT_NAME.search("/".join(parts[:end])):
            break
        expanded = long_path("\\".join(parts[:end]))
        if expanded is not None:
            return "/".join([expanded.replace("\\", "/").rstrip("/"), *parts[end:]])
    return path


def normalize_path(value: str, home: str) -> str | None:
    text = value.strip()
    if not text or len(text) > MAX_PATH_TEXT or "\n" in text or "\x00" in text:
        return None
    if text.lower().startswith("file://"):
        text = unquote(urlsplit(text).path)
        if DRIVE_URL_PATH.match(text):
            text = text[1:]
    text = HOME_TOKENS.sub(lambda _: home, text, count=1)
    text = _windows_path(text.replace("\\", "/"))
    prefix = "//" if text.startswith("//") else ""
    normalized = posixpath.normpath(text[len(prefix) :]) if text[len(prefix) :] else ""
    if not prefix:
        normalized = expand_short_names(normalized)
    return (prefix + normalized).lower()


def path_glob(pattern: str, home: str) -> re.Pattern[str]:
    normalized = normalize_path(pattern, home) or pattern.lower()
    return re.compile(_translate(normalized, separator="/"), re.IGNORECASE | re.DOTALL)


def hosts_in(text: str) -> Iterator[str]:
    for match in URL.finditer(text):
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if host:
            yield host.rstrip(".").lower()


def home_text(home: str) -> str:
    return home.replace("\\", "/").rstrip("/").lower()
