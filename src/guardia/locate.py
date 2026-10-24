from __future__ import annotations

import bisect
import json
import re

from guardia.model import json_pointer

_NEWLINE = re.compile(r"\n")
_WHITESPACE = re.compile(r"[ \t\r\n]*")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_SCALAR = re.compile(r"[^,\]\}\s]+")
_TOML_HEADER = re.compile(
    r"^[ \t]*\[(?P<name>[^\[\]\r\n]+)\][ \t]*(?:#[^\r\n]*)?\r?$", re.MULTILINE
)


class LineIndex:
    def __init__(self, text: str) -> None:
        self._newlines = [match.start() for match in _NEWLINE.finditer(text)]

    def line(self, position: int) -> int:
        return bisect.bisect_left(self._newlines, position) + 1


def _skip(text: str, position: int) -> int:
    match = _WHITESPACE.match(text, position)
    return match.end() if match else position


def _next_member(text: str, frame: list[object], position: int) -> tuple[str, int]:
    kind, pointer = frame[0], str(frame[1])
    if kind == "{":
        match = _STRING.match(text, position)
        if match is None:
            raise ValueError("expected key")
        key = json.loads(match.group())
        position = _skip(text, match.end())
        if text[position] != ":":
            raise ValueError("expected colon")
        return pointer + json_pointer(key), _skip(text, position + 1)
    index = int(str(frame[2]))
    frame[2] = index + 1
    return f"{pointer}/{index}", position


def json_lines(text: str) -> dict[str, int]:
    lines: dict[str, int] = {}
    index = LineIndex(text)
    try:
        position = _skip(text, 0)
        if position >= len(text):
            return lines
        stack: list[list[object]] = []
        pointer = ""
        while True:
            lines[pointer] = index.line(position)
            char = text[position]
            if char in "{[":
                stack.append([char, pointer, 0])
                position = _skip(text, position + 1)
                if text[position] in "}]":
                    stack.pop()
                    position += 1
                else:
                    pointer, position = _next_member(text, stack[-1], position)
                    continue
            else:
                pattern = _STRING if char == '"' else _SCALAR
                match = pattern.match(text, position)
                if match is None:
                    raise ValueError("unexpected token")
                position = match.end()
            while stack:
                position = _skip(text, position)
                char = text[position]
                if char == ",":
                    position = _skip(text, position + 1)
                    pointer, position = _next_member(text, stack[-1], position)
                    break
                if char in "}]":
                    stack.pop()
                    position += 1
                    continue
                raise ValueError("unexpected character")
            else:
                return lines
    except (IndexError, ValueError):
        return lines


def _toml_key_parts(header: str) -> list[str]:
    parts: list[str] = []
    for raw in re.findall(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|[^.\s]+', header):
        if raw.startswith('"'):
            parts.append(json.loads(raw))
        elif raw.startswith("'"):
            parts.append(raw[1:-1])
        else:
            parts.append(raw)
    return parts


def toml_table_lines(text: str) -> dict[str, int]:
    index = LineIndex(text)
    lines: dict[str, int] = {}
    for match in _TOML_HEADER.finditer(text):
        pointer = json_pointer(*_toml_key_parts(match["name"]))
        lines.setdefault(pointer, index.line(match.start("name")))
    return lines
