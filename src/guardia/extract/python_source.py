from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from guardia.extract.code_python import python_signals
from guardia.extract.common import ExtractionError, build_tool
from guardia.model import CodeSignal, Location, TextField, ToolDefinition, ToolKind

DECORATOR_KINDS: Mapping[str, ToolKind] = {
    "tool": ToolKind.TOOL,
    "prompt": ToolKind.PROMPT,
    "resource": ToolKind.RESOURCE,
}
TOOL_CONSTRUCTORS = frozenset({"Tool", "Prompt", "Resource"})
INSTRUCTION_OWNERS = frozenset({"FastMCP", "Server", "MCPServer", "McpServer"})
SKIPPED_PARAMETERS = frozenset({"self", "cls", "ctx", "context"})
PLACEHOLDER = "{…}"
MAX_REPEATED_LENGTH = 200_000


class _Module:
    def __init__(self, tree: ast.Module) -> None:
        self.constants: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    text = self.text(node.value)
                    if text is not None:
                        self.constants[target.id] = text

    def text(self, node: ast.AST | None, depth: int = 0) -> str | None:
        if node is None or depth > 50:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                part = self.text(value, depth + 1)
                parts.append(part if part is not None else PLACEHOLDER)
            return "".join(parts)
        if isinstance(node, ast.FormattedValue):
            return self.text(node.value, depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            text = self.text(node.left, depth + 1)
            count = node.right
            if text is None:
                text, count = self.text(node.right, depth + 1), node.left
            if (
                text is not None
                and isinstance(count, ast.Constant)
                and isinstance(count.value, int)
                and 0 <= count.value * max(len(text), 1) <= MAX_REPEATED_LENGTH
            ):
                return text * count.value
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.text(node.left, depth + 1)
            right = self.text(node.right, depth + 1)
            if left is None and right is None:
                return None
            return (left if left is not None else PLACEHOLDER) + (
                right if right is not None else PLACEHOLDER
            )
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("strip", "format", "dedent")
        ):
            return self.text(node.func.value, depth + 1)
        return None

    def literal(self, node: ast.AST | None) -> Any:
        if node is None:
            return None
        text = self.text(node)
        if text is not None:
            return text
        if isinstance(node, ast.Call):
            return {
                keyword.arg: self.literal(keyword.value)
                for keyword in node.keywords
                if keyword.arg is not None
            }
        try:
            return ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            return None


def _attribute_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _decorator_kind(decorator: ast.AST) -> tuple[ToolKind, ast.Call | None] | None:
    call = decorator if isinstance(decorator, ast.Call) else None
    name = _attribute_name(call.func if call else decorator)
    kind = DECORATOR_KINDS.get(name or "")
    return (kind, call) if kind else None


def _keyword(call: ast.Call | None, name: str) -> ast.AST | None:
    if call is None:
        return None
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _field_description(module: _Module, node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Call) and _attribute_name(node.func) in ("Field", "Parameter"):
        return module.text(_keyword(node, "description"))
    return None


def _parameter_schema(
    module: _Module, function: ast.FunctionDef | ast.AsyncFunctionDef
) -> dict[str, Any]:
    arguments = function.args
    positional = [*arguments.posonlyargs, *arguments.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(arguments.defaults))
    defaults.extend(arguments.defaults)
    pairs = list(zip(positional, defaults, strict=True))
    pairs.extend(zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True))
    properties: dict[str, Any] = {}
    for argument, default in pairs:
        annotation = argument.annotation
        annotation_text = ast.unparse(annotation) if annotation is not None else ""
        if argument.arg in SKIPPED_PARAMETERS or "Context" in annotation_text:
            continue
        schema: dict[str, Any] = {"type": annotation_text or "any"}
        description = _field_description(module, default)
        if (
            isinstance(annotation, ast.Subscript)
            and _attribute_name(annotation.value) == "Annotated"
            and isinstance(annotation.slice, ast.Tuple)
        ):
            for meta in annotation.slice.elts[1:]:
                description = description or module.text(meta) or _field_description(module, meta)
        if description:
            schema["description"] = description
        if default is not None and description is None:
            value = module.literal(default)
            if isinstance(value, str | int | float | bool):
                schema["default"] = value
        elif isinstance(default, ast.Call):
            value = module.literal(_keyword(default, "default"))
            if isinstance(value, str | int | float | bool):
                schema["default"] = value
        properties[argument.arg] = schema
    return {"type": "object", "properties": properties} if properties else {}


def _locator(path: Path, line: int) -> Any:
    def locate(pointer: str) -> Location:
        return Location(path, pointer, line)

    return locate


def _decorated_tools(
    module: _Module, tree: ast.Module, path: Path, origin: str
) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in node.decorator_list:
            matched = _decorator_kind(decorator)
            if matched is None:
                continue
            kind, call = matched
            name = module.text(_keyword(call, "name")) or node.name
            described = _keyword(call, "description")
            description = module.text(described) or ""
            description_line = getattr(described, "lineno", None)
            if not description:
                description = ast.get_docstring(node) or ""
                description_line = node.body[0].lineno if description else None
            annotations = module.literal(_keyword(call, "annotations"))
            extra: list[TextField] = []
            title = module.text(_keyword(call, "title"))
            line = getattr(decorator, "lineno", node.lineno)
            if title:
                extra.append(TextField("title", title, Location(path, "", line)))
            uri = module.text(call.args[0]) if call is not None and call.args else None
            tools.append(
                build_tool(
                    kind=kind,
                    name=uri if kind is ToolKind.RESOURCE and uri else name,
                    description=description,
                    origin=origin,
                    locate=_locator(path, line),
                    input_schema=_parameter_schema(module, node),
                    annotations=annotations if isinstance(annotations, dict) else None,
                    extra_fields=extra,
                    description_location=Location(path, "", description_line or line),
                )
            )
            break
    return tools


def _constructed_tools(
    module: _Module, tree: ast.Module, path: Path, origin: str
) -> list[ToolDefinition]:
    tools: list[ToolDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = _attribute_name(node.func)
        locate = _locator(path, node.lineno)
        if callee in TOOL_CONSTRUCTORS:
            name = module.text(_keyword(node, "name"))
            if not name:
                continue
            schema = module.literal(_keyword(node, "inputSchema") or _keyword(node, "input_schema"))
            annotations = module.literal(_keyword(node, "annotations"))
            tools.append(
                build_tool(
                    kind=ToolKind[callee.upper()] if callee != "Tool" else ToolKind.TOOL,
                    name=name,
                    description=module.text(_keyword(node, "description")) or "",
                    origin=origin,
                    locate=locate,
                    input_schema=schema if isinstance(schema, dict) else None,
                    annotations=annotations if isinstance(annotations, dict) else None,
                )
            )
        elif callee in INSTRUCTION_OWNERS:
            instructions = module.text(_keyword(node, "instructions"))
            if instructions:
                tools.append(
                    build_tool(
                        kind=ToolKind.INSTRUCTIONS,
                        name="instructions",
                        description=instructions,
                        origin=origin,
                        locate=locate,
                    )
                )
        elif callee == "add_tool":
            name = module.text(_keyword(node, "name"))
            description = module.text(_keyword(node, "description"))
            if name and description:
                tools.append(
                    build_tool(
                        kind=ToolKind.TOOL,
                        name=name,
                        description=description,
                        origin=origin,
                        locate=locate,
                    )
                )
    return tools


def analyze_python(path: Path, text: str) -> tuple[list[ToolDefinition], list[CodeSignal]]:
    try:
        tree = ast.parse(text, filename=str(path))
        module = _Module(tree)
        origin = "python-source"
        tools = _decorated_tools(module, tree, path, origin) + _constructed_tools(
            module, tree, path, origin
        )
        return tools, python_signals(path, tree)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise ExtractionError(type(exc).__name__) from exc


def tools_from_python(path: Path, text: str) -> list[ToolDefinition]:
    return analyze_python(path, text)[0]
