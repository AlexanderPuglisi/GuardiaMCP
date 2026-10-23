from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from guardia.extract.common import Locator, build_tool
from guardia.locate import json_lines
from guardia.model import Location, TextField, ToolDefinition, ToolKind
from guardia.safeio import parse_json, read_text

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
KIND_KEYS = (
    ("tools", ToolKind.TOOL),
    ("prompts", ToolKind.PROMPT),
    ("resources", ToolKind.RESOURCE),
    ("resourceTemplates", ToolKind.RESOURCE),
)


def _locator(path: Path, lines: Mapping[str, int]) -> Locator:
    def locate(pointer: str) -> Location:
        candidate = pointer
        while True:
            line = lines.get(candidate)
            if line is not None or not candidate:
                return Location(path, pointer, line)
            candidate = candidate.rsplit("/", 1)[0]

    return locate


def _entry_tools(
    entries: Any, kind: ToolKind, base: str, origin: str, locate: Locator
) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    if not isinstance(entries, list):
        return tools
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            continue
        name = entry.get("name") or entry.get("uri") or entry.get("uriTemplate")
        if not isinstance(name, str):
            continue
        pointer = f"{base}/{index}"
        description = entry.get("description")
        extra: list[TextField] = []
        for key in ("title", "text"):
            value = entry.get(key)
            if isinstance(value, str):
                extra.append(TextField(key, value, locate(f"{pointer}/{key}")))
        arguments = entry.get("arguments")
        if isinstance(arguments, list):
            for arg_index, argument in enumerate(arguments):
                if isinstance(argument, Mapping) and isinstance(argument.get("description"), str):
                    extra.append(
                        TextField(
                            f"arguments.{argument.get('name', arg_index)}.description",
                            argument["description"],
                            locate(f"{pointer}/arguments/{arg_index}/description"),
                        )
                    )
        schema = entry.get("inputSchema", entry.get("input_schema"))
        annotations = entry.get("annotations")
        tools.append(
            build_tool(
                kind=kind,
                name=name,
                description=description if isinstance(description, str) else "",
                origin=origin,
                locate=locate,
                pointer=pointer,
                description_pointer=f"{pointer}/description",
                input_schema=schema if isinstance(schema, Mapping) else None,
                annotations=annotations if isinstance(annotations, Mapping) else None,
                extra_fields=extra,
            )
        )
    return tools


def tools_from_document(
    path: Path, document: Any, origin: str, text: str = ""
) -> list[ToolDefinition]:
    locate = _locator(path, json_lines(text) if text else {})
    if isinstance(document, list):
        return _entry_tools(document, ToolKind.TOOL, "", origin, locate)
    if not isinstance(document, Mapping):
        return []
    base = ""
    result = document.get("result")
    if isinstance(result, Mapping):
        document, base = result, "/result"
    tools: list[ToolDefinition] = []
    for key, kind in KIND_KEYS:
        tools.extend(_entry_tools(document.get(key), kind, f"{base}/{key}", origin, locate))
    instructions = document.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        tools.append(
            build_tool(
                kind=ToolKind.INSTRUCTIONS,
                name="instructions",
                description=instructions,
                origin=origin,
                locate=locate,
                pointer=f"{base}/instructions",
            )
        )
    return tools


def tools_from_json_file(path: Path, origin: str) -> list[ToolDefinition]:
    text = read_text(path, MAX_DOCUMENT_BYTES)
    parsed = parse_json(text)
    return tools_from_document(path, parsed.value, origin, parsed.text)
