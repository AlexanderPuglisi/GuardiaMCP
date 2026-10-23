from __future__ import annotations

import enum
import json
import math
import stat
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ENTRY_DEPTH = 32


class ReadErrorCode(enum.StrEnum):
    MISSING = "missing"
    NOT_A_FILE = "not_a_file"
    TOO_LARGE = "too_large"
    PERMISSION = "permission"
    IO = "io"
    DECODE = "decode"
    PARSE = "parse"
    TOO_DEEP = "too_deep"


class SafeReadError(Exception):
    def __init__(self, code: ReadErrorCode, detail: str = "") -> None:
        super().__init__(f"{code.value}: {detail}" if detail else code.value)
        self.code = code
        self.detail = detail


@dataclass(slots=True)
class ParsedDocument:
    value: Any
    duplicate_keys: list[str] = field(default_factory=list)
    text: str = ""


def is_network_path(text: str) -> bool:
    return text.strip().strip('"').replace("/", "\\").startswith("\\\\")


def read_bytes(path: Path, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise SafeReadError(ReadErrorCode.NOT_A_FILE)
        if info.st_size > max_bytes:
            raise SafeReadError(ReadErrorCode.TOO_LARGE, f"{info.st_size} > {max_bytes} bytes")
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except FileNotFoundError as exc:
        raise SafeReadError(ReadErrorCode.MISSING) from exc
    except PermissionError as exc:
        raise SafeReadError(ReadErrorCode.PERMISSION) from exc
    except IsADirectoryError as exc:
        raise SafeReadError(ReadErrorCode.NOT_A_FILE) from exc
    except OSError as exc:
        raise SafeReadError(ReadErrorCode.IO, exc.strerror or type(exc).__name__) from exc
    if len(data) > max_bytes:
        raise SafeReadError(ReadErrorCode.TOO_LARGE, f"> {max_bytes} bytes")
    return data


def decode_text(data: bytes) -> str:
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16")
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SafeReadError(ReadErrorCode.DECODE, f"byte {exc.start}") from exc


def read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    return decode_text(read_bytes(path, max_bytes))


def _finite(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"number out of range: {text[:20]}")
    return value


def _reject_constant(name: str) -> Any:
    raise SafeReadError(ReadErrorCode.PARSE, f"non-standard constant {name}")


def parse_json(text: str, *, jsonc: bool = False) -> ParsedDocument:
    duplicates: list[str] = []

    def collect_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    source = strip_jsonc(text) if jsonc else text
    try:
        value = json.loads(
            source,
            object_pairs_hook=collect_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite,
        )
    except RecursionError as exc:
        raise SafeReadError(ReadErrorCode.TOO_DEEP) from exc
    except json.JSONDecodeError as exc:
        raise SafeReadError(
            ReadErrorCode.PARSE, f"line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise SafeReadError(ReadErrorCode.PARSE, str(exc)[:200]) from exc
    return ParsedDocument(value, duplicates, source)


def parse_toml(text: str) -> ParsedDocument:
    try:
        return ParsedDocument(tomllib.loads(text, parse_float=_finite), text=text)
    except RecursionError as exc:
        raise SafeReadError(ReadErrorCode.TOO_DEEP) from exc
    except tomllib.TOMLDecodeError as exc:
        raise SafeReadError(ReadErrorCode.PARSE, str(exc)) from exc
    except ValueError as exc:
        raise SafeReadError(ReadErrorCode.PARSE, str(exc)[:200]) from exc


def strip_jsonc(text: str) -> str:
    out: list[str] = []
    index, length = 0, len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end == -1:
                raise SafeReadError(ReadErrorCode.PARSE, "unterminated block comment")
            out.append("\n" * text.count("\n", index, end))
            index = end + 2
            continue
        out.append(char)
        index += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == ",":
            lookahead = index + 1
            while lookahead < length and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead < length and text[lookahead] in "}]":
                index += 1
                continue
        out.append(char)
        index += 1
    return "".join(out)


def depth_exceeds(value: Any, limit: int = MAX_ENTRY_DEPTH) -> bool:
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > limit:
            return True
        children: Iterable[Any]
        if isinstance(current, dict):
            children = current.values()
        elif isinstance(current, list):
            children = current
        else:
            continue
        stack.extend((child, depth + 1) for child in children)
    return False
