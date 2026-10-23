from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from guardia.extract.common import build_tool
from guardia.inventory.skills import SkillDocument
from guardia.model import (
    CodeSignal,
    Location,
    SignalKind,
    TextField,
    ToolDefinition,
    ToolKind,
    sha256_hex,
)
from guardia.scanner.checks import DOWNLOAD_EXECUTE

BROAD_TOOL = re.compile(
    r"^\s*(\*|bash|bash\(\s*\*?\s*\)|powershell|powershell\(\s*\*?\s*\)|computer|all|any)\s*$",
    re.IGNORECASE,
)
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`([^`\n]+)`")


def _key_lines(text: str, body_line: int) -> dict[str, int]:
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines()[: max(body_line - 1, 0)], start=1):
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:", line)
        if match:
            lines.setdefault(match.group(1), number)
    return lines


def body_blocks(document: SkillDocument) -> Iterator[tuple[str, str, int]]:
    label, start = "body", document.body_line
    buffer: list[str] = []
    in_code = False
    for offset, line in enumerate(document.body.splitlines()):
        number = document.body_line + offset
        if FENCE.match(line):
            if buffer:
                yield label, "\n".join(buffer), start
            buffer, in_code = [], not in_code
            label, start = ("body.code" if in_code else "body"), number + 1
            continue
        if not line.strip() and not in_code:
            if buffer:
                yield label, "\n".join(buffer), start
            buffer, start = [], number + 1
            continue
        if not buffer:
            start = number
        buffer.append(line)
    if buffer:
        yield label, "\n".join(buffer), start


def skill_definition(path: Path, name: str, document: SkillDocument) -> ToolDefinition:
    keys = _key_lines(document.text, document.body_line)

    def at(line: int | None) -> Location:
        return Location(path, "", line)

    description = document.frontmatter.get("description")
    description_text = description if isinstance(description, str) else ""
    extra: list[TextField] = []
    for key, value in document.frontmatter.items():
        if key in ("name", "description"):
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, str) and item:
                extra.append(TextField(f"frontmatter.{key}", item, at(keys.get(key))))
    for label, text, line in body_blocks(document):
        extra.append(TextField(label, text, at(line)))
    allowed = document.frontmatter.get("allowed-tools")
    annotations = {
        "body_sha256": sha256_hex(document.body.encode("utf-8")),
        "allowed-tools": ", ".join(allowed) if isinstance(allowed, list) else str(allowed or ""),
    }
    return build_tool(
        kind=ToolKind.SKILL,
        name=name,
        description=description_text,
        origin="skill",
        locate=lambda pointer: Location(path, pointer, keys.get("name", 1)),
        annotations=annotations,
        extra_fields=extra,
        description_location=at(keys.get("description")),
    )


def _allowed_tools(document: SkillDocument) -> list[str]:
    allowed = document.frontmatter.get("allowed-tools")
    if isinstance(allowed, list):
        return [str(item) for item in allowed]
    if isinstance(allowed, str):
        return [part for part in re.split(r"[,\s]+(?![^()]*\))", allowed) if part]
    return []


def skill_signals(path: Path, document: SkillDocument) -> list[CodeSignal]:
    keys = _key_lines(document.text, document.body_line)
    signals: list[CodeSignal] = []
    broad = [tool for tool in _allowed_tools(document) if BROAD_TOOL.match(tool)]
    if broad:
        signals.append(
            CodeSignal(
                SignalKind.BROAD_TOOLS,
                Location(path, "", keys.get("allowed-tools")),
                "allowed-tools: " + ", ".join(broad),
                ", ".join(broad),
            )
        )
    for label, text, line in body_blocks(document):
        spans = [text] if label == "body.code" else INLINE_CODE.findall(text)
        for span in spans:
            match = DOWNLOAD_EXECUTE.search(span)
            if match and "://" in match.group(0):
                offset = text.count("\n", 0, text.find(span))
                signals.append(
                    CodeSignal(
                        SignalKind.DOWNLOAD_EXEC,
                        Location(path, "", line + offset),
                        match.group(0)[:160],
                        "instructions",
                    )
                )
                break
    return signals


def shell_script_signals(path: Path, text: str) -> list[CodeSignal]:
    signals: list[CodeSignal] = []
    for match in DOWNLOAD_EXECUTE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        signals.append(
            CodeSignal(
                SignalKind.DOWNLOAD_EXEC, Location(path, "", line), match.group(0)[:160], "script"
            )
        )
        if len(signals) >= 5:
            break
    return signals
