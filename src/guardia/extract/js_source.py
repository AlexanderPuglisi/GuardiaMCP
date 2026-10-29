from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from guardia.extract.common import ExtractionError, build_tool
from guardia.extract.strings import classify
from guardia.locate import LineIndex
from guardia.model import (
    CAPABILITY_SIGNALS,
    CodeSignal,
    Location,
    SignalKind,
    TextField,
    ToolDefinition,
    ToolKind,
)

MAX_TOKENS = 3_000_000
PLACEHOLDER = "{…}"

_SKIP = re.compile(r"(?:\s+|//[^\n]*|/\*.*?\*/)+", re.DOTALL)
_STRING = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"", re.DOTALL)
_IDENT = re.compile(r"[A-Za-z_$\u00c0-\uffff][\w$\u00c0-\uffff]*")
_NUMBER = re.compile(r"\d[\w.]*|\.\d[\w]*")
_PUNCT = re.compile(r"=>|\.\.\.|\?\.|\?\?|[{}()\[\];,:.?=+\-*/%<>&|^!~@#]")
_ESCAPE = re.compile(r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|\r\n|.)", re.DOTALL)
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
_SURROGATE = re.compile("[\ud800-\udfff]")
REGEX_KEYWORDS = frozenset(
    {
        "return",
        "typeof",
        "case",
        "do",
        "else",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "yield",
        "await",
    }
)
REGEX_AFTER_PUNCT = frozenset("(,=:[!&|?{};+-*%<>~^") | {"=>", "??"}

CALL_KINDS: Mapping[str, ToolKind] = {
    "tool": ToolKind.TOOL,
    "registerTool": ToolKind.TOOL,
    "addTool": ToolKind.TOOL,
    "prompt": ToolKind.PROMPT,
    "registerPrompt": ToolKind.PROMPT,
    "resource": ToolKind.RESOURCE,
    "registerResource": ToolKind.RESOURCE,
}
SERVER_CLASSES = frozenset({"McpServer", "Server", "FastMCP"})
TEMPLATE_TAGS = frozenset({"dedent", "outdent", "stripIndent", "stripIndents", "trim"})
TOOL_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/:]{0,127}$")


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str
    position: int


def _unescape(match: re.Match[str]) -> str:
    body = match.group(1)
    if body.startswith("u{"):
        return chr(min(int(body[2:-1], 16), 0x10FFFF))
    if body.startswith("u") and len(body) == 5:
        return chr(int(body[1:], 16))
    if body.startswith("x") and len(body) == 3:
        return chr(int(body[1:], 16))
    if body in ("\n", "\r\n"):
        return ""
    return _SIMPLE_ESCAPES.get(body, body)


def decode_string(literal: str) -> str:
    text = _ESCAPE.sub(_unescape, literal)
    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def _scan_template(text: str, start: int) -> tuple[str, int]:
    parts: list[str] = []
    index = start + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\" and index + 1 < length:
            parts.append(text[index : index + 2])
            index += 2
        elif char == "`":
            return decode_string("".join(parts)), index + 1
        elif text.startswith("${", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                index += 1
            parts.append(PLACEHOLDER)
        else:
            parts.append(char)
            index += 1
    return decode_string("".join(parts)), length


def _scan_regex(text: str, start: int) -> int:
    index = start + 1
    in_class = False
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n":
            return start + 1
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < length and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            return index
        index += 1
    return start + 1


def _regex_allowed(previous: Token | None) -> bool:
    if previous is None:
        return True
    if previous.kind == "punct":
        return previous.value in REGEX_AFTER_PUNCT
    return previous.kind == "ident" and previous.value in REGEX_KEYWORDS


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    length = len(text)
    previous: Token | None = None
    while index < length and len(tokens) < MAX_TOKENS:
        skipped = _SKIP.match(text, index)
        if skipped:
            index = skipped.end()
            continue
        char = text[index]
        token: Token | None = None
        if char in "'\"":
            match = _STRING.match(text, index)
            if match:
                token = Token("str", decode_string(match.group()[1:-1]), index)
                index = match.end()
        elif char == "`":
            value, end = _scan_template(text, index)
            token = Token("str", value, index)
            index = end
        elif char == "/" and _regex_allowed(previous):
            end = _scan_regex(text, index)
            if end > index + 1:
                token = Token("regex", "", index)
                index = end
        if token is None:
            for kind, pattern in (("ident", _IDENT), ("num", _NUMBER), ("punct", _PUNCT)):
                match = pattern.match(text, index)
                if match:
                    token = Token(kind, match.group(), index)
                    index = match.end()
                    break
        if token is None:
            index += 1
            continue
        tokens.append(token)
        previous = token
    return tokens


class _Parser:
    def __init__(self, path: Path, text: str) -> None:
        self.path = path
        self.tokens = tokenize(text)
        self.lines = LineIndex(text)
        self.closing: dict[int, int] = {}
        stack: list[int] = []
        pairs = {"}": "{", ")": "(", "]": "["}
        for position, token in enumerate(self.tokens):
            if token.kind != "punct":
                continue
            if token.value in "{([":
                stack.append(position)
            elif token.value in pairs and stack:
                opener = stack.pop()
                if self.tokens[opener].value == pairs[token.value]:
                    self.closing[opener] = position
        self.constants: dict[str, str] = {}
        for position, token in enumerate(self.tokens[:-3]):
            if (
                token.kind == "ident"
                and token.value in ("const", "let", "var")
                and self.tokens[position + 1].kind == "ident"
                and self.is_punct(position + 2, "=")
            ):
                value = self.string_at(position + 3)
                if value is not None:
                    self.constants.setdefault(self.tokens[position + 1].value, value[0])

    def is_punct(self, index: int, value: str) -> bool:
        return (
            0 <= index < len(self.tokens)
            and self.tokens[index].kind == "punct"
            and self.tokens[index].value == value
        )

    def location(self, index: int) -> Location:
        token = self.tokens[min(index, len(self.tokens) - 1)]
        return Location(self.path, "", self.lines.line(token.position))

    def string_at(self, index: int, depth: int = 0) -> tuple[str, int] | None:
        tokens = self.tokens
        if index >= len(tokens) or depth > 20:
            return None
        token = tokens[index]
        if token.kind == "ident" and token.value in TEMPLATE_TAGS and index + 1 < len(tokens):
            return self.string_at(index + 1, depth + 1)
        if token.kind == "ident" and token.value in self.constants:
            return self.constants[token.value], index + 1
        if self.is_punct(index, "["):
            return self._joined_array(index, depth + 1)
        if self.is_punct(index, "("):
            inner = self.string_at(index + 1, depth + 1)
            if inner and self.is_punct(inner[1], ")"):
                return inner[0], inner[1] + 1
            return None
        if token.kind != "str":
            return None
        parts = [token.value]
        index += 1
        while self.is_punct(index, "+") and index + 1 < len(tokens):
            following = tokens[index + 1]
            if following.kind == "str":
                parts.append(following.value)
                index += 2
            else:
                parts.append(PLACEHOLDER)
                index += 2
        return "".join(parts), index

    def _joined_array(self, index: int, depth: int) -> tuple[str, int] | None:
        end = self.closing.get(index)
        if end is None or end - index > 20_000:
            return None
        items: list[str] = []
        cursor = index + 1
        while cursor < end:
            item = self.string_at(cursor, depth + 1)
            if item is None:
                return None
            items.append(item[0])
            cursor = item[1]
            if self.is_punct(cursor, ","):
                cursor += 1
        if not (
            self.is_punct(end + 1, ".")
            and end + 2 < len(self.tokens)
            and self.tokens[end + 2].value == "join"
            and self.is_punct(end + 3, "(")
        ):
            return None
        separator = self.string_at(end + 4)
        joiner = separator[0] if separator else ","
        close = self.closing.get(end + 3, end + 4)
        return joiner.join(items), close + 1

    def members(self, opener: int) -> dict[str, int]:
        end = self.closing.get(opener)
        result: dict[str, int] = {}
        if end is None:
            return result
        cursor = opener + 1
        while cursor < end:
            token = self.tokens[cursor]
            if token.kind in ("ident", "str") and self.is_punct(cursor + 1, ":"):
                result.setdefault(token.value, cursor + 2)
            elif (
                token.kind == "ident"
                and (self.is_punct(cursor - 1, "{") or self.is_punct(cursor - 1, ","))
                and (self.is_punct(cursor + 1, ",") or cursor + 1 == end)
            ):
                result.setdefault(token.value, cursor)
            if token.kind == "punct" and token.value in "{([" and cursor in self.closing:
                cursor = self.closing[cursor] + 1
                continue
            cursor += 1
        return result

    def described_fields(self, start: int, end: int) -> list[TextField]:
        fields: list[TextField] = []
        cursor = start
        while cursor < end:
            token = self.tokens[cursor]
            if (
                token.kind == "ident"
                and token.value == "describe"
                and self.is_punct(cursor - 1, ".")
                and self.is_punct(cursor + 1, "(")
            ):
                text = self.string_at(cursor + 2)
                if text:
                    label = f"inputSchema.{self._owner_key(cursor)}.description"
                    fields.append(TextField(label, text[0], self.location(cursor)))
            elif (
                token.kind in ("ident", "str")
                and token.value in ("description", "title", "default")
                and self.is_punct(cursor + 1, ":")
            ):
                text = self.string_at(cursor + 2)
                if text:
                    label = f"inputSchema.{self._owner_key(cursor)}.{token.value}"
                    fields.append(TextField(label, text[0], self.location(cursor)))
            cursor += 1
        return fields

    def _owner_key(self, index: int) -> str:
        depth = 0
        cursor = index - 1
        limit = max(0, index - 80)
        while cursor >= limit:
            token = self.tokens[cursor]
            if token.kind == "punct" and token.value in ")]}":
                depth += 1
            elif token.kind == "punct" and token.value in "([{":
                if depth == 0:
                    return "?"
                depth -= 1
            elif depth == 0 and token.kind in ("ident", "str") and self.is_punct(cursor + 1, ":"):
                return token.value
            cursor -= 1
        return "?"

    def _top_comma(self, start: int, end: int) -> int | None:
        index = start
        while index < end:
            close = self.closing.get(index)
            if close is not None:
                index = close + 1
                continue
            if self.is_punct(index, ","):
                return index
            index += 1
        return None

    def call_tools(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for index, token in enumerate(self.tokens):
            kind = CALL_KINDS.get(token.value) if token.kind == "ident" else None
            if (
                kind is None
                or not self.is_punct(index - 1, ".")
                or not self.is_punct(index + 1, "(")
            ):
                continue
            call_end = self.closing.get(index + 1, len(self.tokens))
            name = self.string_at(index + 2)
            if name is not None and self.is_punct(name[1], ","):
                tool_name, name_end = name[0], name[1]
            else:
                comma = self._top_comma(index + 2, call_end)
                if comma is None:
                    continue
                tool_name, name_end = "(dynamic)", comma
            cursor = name_end + 1
            description = ""
            extra: list[TextField] = []
            described = self.string_at(cursor)
            if described is not None:
                description = described[0]
                cursor = described[1] + 1 if self.is_punct(described[1], ",") else described[1]
            if self.is_punct(cursor, "{"):
                members = self.members(cursor)
                config_keys = {"description", "title", "inputSchema", "argsSchema", "annotations"}
                if config_keys & members.keys():
                    if not description and "description" in members:
                        found = self.string_at(members["description"])
                        description = found[0] if found else ""
                    if "title" in members:
                        found = self.string_at(members["title"])
                        if found:
                            location = self.location(members["title"])
                            extra.append(TextField("title", found[0], location))
                    for key in ("inputSchema", "argsSchema"):
                        if key in members and self.is_punct(members[key], "{"):
                            start = members[key]
                            end = self.closing.get(start, call_end)
                            extra.extend(self.described_fields(start + 1, end))
                else:
                    object_end = self.closing.get(cursor, call_end)
                    extra.extend(self.described_fields(cursor + 1, object_end))
            tools.append(self._tool(kind, tool_name, description, index, extra))
        return tools

    def object_tools(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for opener, closer in self.closing.items():
            if self.tokens[opener].value != "{":
                continue
            members = self.members(opener)
            if "name" not in members or "description" not in members:
                continue
            name = self.string_at(members["name"])
            description = self.string_at(members["description"])
            if name is None or description is None or not TOOL_NAME.match(name[0]):
                continue
            kind = ToolKind.TOOL
            if "uri" in members or "uriTemplate" in members:
                kind = ToolKind.RESOURCE
            elif "arguments" in members and "inputSchema" not in members:
                kind = ToolKind.PROMPT
            extra: list[TextField] = []
            for key in ("inputSchema", "input_schema", "parameters", "arguments"):
                if key in members:
                    start = members[key]
                    end = self.closing.get(start, closer)
                    extra.extend(self.described_fields(start, end))
            tools.append(self._tool(kind, name[0], description[0], opener, extra))
        return tools

    def instructions(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for index, token in enumerate(self.tokens):
            if not (
                token.kind == "ident"
                and token.value == "new"
                and index + 2 < len(self.tokens)
                and self.tokens[index + 1].value in SERVER_CLASSES
                and self.is_punct(index + 2, "(")
            ):
                continue
            end = self.closing.get(index + 2, len(self.tokens))
            cursor = index + 3
            while cursor < end:
                current = self.tokens[cursor]
                if current.value == "instructions" and self.is_punct(cursor + 1, ":"):
                    text = self.string_at(cursor + 2)
                    if text:
                        tools.append(
                            self._tool(ToolKind.INSTRUCTIONS, "instructions", text[0], cursor, [])
                        )
                    break
                cursor += 1
        return tools

    def _tool(
        self, kind: ToolKind, name: str, description: str, index: int, extra: list[TextField]
    ) -> ToolDefinition:
        location = self.location(index)
        properties: dict[str, dict[str, str]] = {}
        for field in extra:
            parts = field.label.split(".")
            if parts[0] == "inputSchema" and len(parts) == 3:
                properties.setdefault(parts[1], {})[parts[2]] = field.text
        return build_tool(
            kind=kind,
            name=name,
            description=description,
            origin="js-source",
            locate=lambda pointer: Location(self.path, pointer, location.line),
            input_schema={"type": "object", "properties": properties} if properties else None,
            scan_schema=False,
            extra_fields=extra,
        )


def tools_from_javascript(path: Path, text: str) -> list[ToolDefinition]:
    return analyze_javascript(path, text)[0]


PROCESS_MODULES = frozenset(
    {"child_process", "node:child_process", "execa", "shelljs", "cross-spawn", "node-pty"}
)
NETWORK_MODULES = frozenset(
    {
        "http",
        "https",
        "node:http",
        "node:https",
        "net",
        "node:net",
        "tls",
        "node:tls",
        "dgram",
        "node:dgram",
        "undici",
        "axios",
        "node-fetch",
        "cross-fetch",
        "ws",
        "got",
        "superagent",
        "socket.io-client",
    }
)
FILE_READERS = frozenset({"readFile", "readFileSync", "createReadStream"})
SHELL_EXECUTORS = frozenset({"exec", "execSync"})
DECODER_HINTS = frozenset({"atob", "fromCharCode", "unescape", "base64", "hex", "base64url"})
VM_RUNNERS = frozenset({"runInNewContext", "runInThisContext", "runInContext", "compileFunction"})
MAX_JS_SIGNALS_PER_KIND = 20


def _js_signals(parser: _Parser) -> list[CodeSignal]:
    tokens = parser.tokens
    signals: list[CodeSignal] = []
    counts: dict[SignalKind, int] = {}

    def add(kind: SignalKind, index: int, evidence: str = "", detail: str = "") -> None:
        limit = 1 if kind in CAPABILITY_SIGNALS else MAX_JS_SIGNALS_PER_KIND
        if counts.get(kind, 0) >= limit:
            return
        counts[kind] = counts.get(kind, 0) + 1
        signals.append(CodeSignal(kind, parser.location(index), evidence[:160], detail))

    def call_range(open_index: int) -> range:
        return range(open_index + 1, parser.closing.get(open_index, open_index + 1))

    def decoding(open_index: int) -> bool:
        return any(tokens[i].value in DECODER_HINTS for i in call_range(open_index))

    def all_strings(open_index: int) -> bool:
        return all(
            tokens[i].kind == "str" or parser.is_punct(i, ",") for i in call_range(open_index)
        )

    for index, token in enumerate(tokens):
        value = token.value
        if token.kind == "str":
            if value in PROCESS_MODULES:
                add(SignalKind.PROCESS, index, value)
            elif (
                value in NETWORK_MODULES and index > 0 and tokens[index - 1].value in ("(", "from")
            ):
                add(SignalKind.NETWORK, index, value)
            for kind, evidence, detail in classify(value):
                add(kind, index, evidence, detail)
            continue
        if token.kind != "ident" or not parser.is_punct(index + 1, "("):
            continue
        after_dot = parser.is_punct(index - 1, ".")
        if value == "fetch" and not after_dot:
            add(SignalKind.NETWORK, index, "fetch")
        elif value in FILE_READERS:
            add(SignalKind.FILE_READ, index, value)
        elif value in SHELL_EXECUTORS:
            first = index + 2
            if (
                first < len(tokens)
                and tokens[first].kind == "str"
                and (PLACEHOLDER in tokens[first].value or parser.is_punct(first + 1, "+"))
            ):
                add(SignalKind.SHELL_STRING, index, f"{value}({tokens[first].value[:120]}")
        elif (value == "eval" and not after_dot) or value == "Function" or value in VM_RUNNERS:
            if decoding(index + 1):
                add(SignalKind.DECODE_EXEC, index, value)
            elif not all_strings(index + 1):
                add(SignalKind.DYNAMIC_EVAL, index, value)
        elif (
            value == "stringify"
            and after_dot
            and index >= 2
            and tokens[index - 2].value == "JSON"
            and index + 4 < len(tokens)
            and tokens[index + 2].value == "process"
            and tokens[index + 4].value == "env"
            and parser.is_punct(index + 5, ")")
        ):
            add(SignalKind.ENV_DUMP, index, "JSON.stringify(process.env)")
    return signals


def analyze_javascript(path: Path, text: str) -> tuple[list[ToolDefinition], list[CodeSignal]]:
    try:
        parser = _Parser(path, text)
        tools = parser.call_tools() + parser.object_tools() + parser.instructions()
        return tools, _js_signals(parser)
    except (RecursionError, MemoryError, IndexError, ValueError) as exc:
        raise ExtractionError(type(exc).__name__) from exc
