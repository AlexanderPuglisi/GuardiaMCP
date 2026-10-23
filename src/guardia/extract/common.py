from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from guardia.model import (
    Location,
    TextField,
    ToolDefinition,
    ToolKind,
    frozen_mapping,
    json_pointer,
)

MAX_SCHEMA_NODES = 2000
MAX_SCHEMA_DEPTH = 32
SCHEMA_TEXT_KEYS = ("description", "title", "default", "const", "examples", "enum", "pattern")

Locator = Callable[[str], Location]


class ExtractionError(Exception):
    pass


def _texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def schema_text_fields(
    schema: Any, base_label: str, base_pointer: str, locate: Locator
) -> list[TextField]:
    fields: list[TextField] = []
    stack: list[tuple[Any, str, str, int]] = [(schema, base_label, base_pointer, 0)]
    visited = 0
    while stack and visited < MAX_SCHEMA_NODES:
        node, label, pointer, depth = stack.pop()
        visited += 1
        if depth > MAX_SCHEMA_DEPTH or not isinstance(node, Mapping):
            continue
        for key in SCHEMA_TEXT_KEYS:
            for index, text in enumerate(_texts(node.get(key))):
                suffix = f"/{index}" if isinstance(node.get(key), list) else ""
                field_pointer = pointer + json_pointer(key) + suffix
                fields.append(TextField(f"{label}.{key}", text, locate(field_pointer)))
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            for name, child in properties.items():
                fields.append(
                    TextField(
                        f"{label}.properties.{name}.name",
                        str(name),
                        locate(pointer + json_pointer("properties", str(name))),
                    )
                )
                stack.append(
                    (
                        child,
                        f"{label}.properties.{name}",
                        pointer + json_pointer("properties", str(name)),
                        depth + 1,
                    )
                )
        for key in ("items", "additionalProperties", "not", "if", "then", "else"):
            child = node.get(key)
            if isinstance(child, Mapping):
                stack.append((child, f"{label}.{key}", pointer + json_pointer(key), depth + 1))
        for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
            children = node.get(key)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    stack.append(
                        (child, f"{label}.{key}[{index}]", f"{pointer}/{key}/{index}", depth + 1)
                    )
        definitions = node.get("$defs") or node.get("definitions")
        if isinstance(definitions, Mapping):
            for name, child in definitions.items():
                stack.append(
                    (
                        child,
                        f"{label}.$defs.{name}",
                        pointer + json_pointer("$defs", str(name)),
                        depth + 1,
                    )
                )
    return fields


def build_tool(
    *,
    kind: ToolKind,
    name: str,
    description: str,
    origin: str,
    locate: Locator,
    pointer: str = "",
    description_pointer: str | None = None,
    input_schema: Mapping[str, Any] | None = None,
    schema_pointer: str | None = None,
    annotations: Mapping[str, Any] | None = None,
    extra_fields: list[TextField] | None = None,
    scan_schema: bool = True,
    description_location: Location | None = None,
) -> ToolDefinition:
    location = locate(pointer)
    fields = [TextField("name", name, location)]
    if description:
        if description_location is None:
            description_location = locate(
                description_pointer if description_pointer is not None else pointer
            )
        fields.append(TextField("description", description, description_location))
    schema = dict(input_schema or {})
    if schema and scan_schema:
        fields.extend(
            schema_text_fields(
                schema,
                "inputSchema",
                schema_pointer if schema_pointer is not None else pointer + "/inputSchema",
                locate,
            )
        )
    for key, value in (annotations or {}).items():
        if isinstance(value, str):
            fields.append(TextField(f"annotations.{key}", value, location))
    fields.extend(extra_fields or [])
    return ToolDefinition(
        kind=kind,
        name=name,
        description=description,
        location=location,
        origin=origin,
        input_schema=frozen_mapping(schema),
        annotations=frozen_mapping(dict(annotations or {})),
        fields=tuple(fields),
    )


def dedupe(tools: list[ToolDefinition]) -> tuple[ToolDefinition, ...]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ToolDefinition] = []
    for tool in tools:
        key = (tool.kind.value, tool.name, tool.description)
        if key not in seen:
            seen.add(key)
            unique.append(tool)
    return tuple(unique)
