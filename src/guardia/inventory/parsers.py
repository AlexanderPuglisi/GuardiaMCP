from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardia.inventory.locations import ConfigFormat, ConfigLocation
from guardia.model import (
    Client,
    ConfigSource,
    Scope,
    ServerEntry,
    Transport,
    frozen_mapping,
    json_pointer,
)
from guardia.safeio import depth_exceeds, is_network_path
from guardia.shield.wrapping import unwrap

TRANSPORT_ALIASES: Mapping[str, Transport] = {
    "stdio": Transport.STDIO,
    "local": Transport.STDIO,
    "http": Transport.HTTP,
    "streamable-http": Transport.HTTP,
    "streamable_http": Transport.HTTP,
    "streamablehttp": Transport.HTTP,
    "sse": Transport.SSE,
    "ws": Transport.WEBSOCKET,
    "websocket": Transport.WEBSOCKET,
}

URL_KEYS = ("url", "serverUrl", "httpUrl")


@dataclass(slots=True)
class ParseOutcome:
    servers: list[ServerEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    projects: list[Path] = field(default_factory=list)
    disabled_project_servers: dict[str, frozenset[str]] = field(default_factory=dict)
    references: list[Path] = field(default_factory=list)

    def warn(self, code: str, detail: str = "") -> None:
        self.warnings.append(f"{code}:{detail}" if detail else code)


def _scalar_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bool | int | float) or value is None:
        return json.dumps(value)
    return None


def _string_tuple(value: Any, pointer: str, outcome: ParseOutcome) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        outcome.warn("invalid_args", pointer)
        return ()
    items: list[str] = []
    for index, item in enumerate(value):
        text = _scalar_text(item)
        if text is None:
            outcome.warn("invalid_arg", f"{pointer}/{index}")
            continue
        items.append(text)
    return tuple(items)


def _string_map(value: Any, pointer: str, outcome: ParseOutcome) -> Mapping[str, str]:
    if value is None:
        return frozen_mapping()
    if not isinstance(value, dict):
        outcome.warn("invalid_map", pointer)
        return frozen_mapping()
    result: dict[str, str] = {}
    for key, item in value.items():
        text = _scalar_text(item)
        if text is None:
            outcome.warn("invalid_map_value", pointer + json_pointer(str(key)))
            continue
        result[str(key)] = text
    return frozen_mapping(result)


def _url_transport(url: str, client: Client) -> Transport:
    lowered = url.lower()
    if lowered.startswith(("ws://", "wss://")):
        return Transport.WEBSOCKET
    if client is Client.GEMINI_CLI or lowered.rstrip("/").endswith("/sse"):
        return Transport.SSE
    return Transport.HTTP


def infer_transport(raw: Mapping[str, Any], client: Client) -> Transport:
    declared = raw.get("type", raw.get("transport"))
    if isinstance(declared, str):
        return TRANSPORT_ALIASES.get(declared.strip().lower(), Transport.UNKNOWN)
    if isinstance(raw.get("command"), str):
        return Transport.STDIO
    if isinstance(raw.get("httpUrl"), str):
        return Transport.HTTP
    url = next((raw[key] for key in URL_KEYS if isinstance(raw.get(key), str)), None)
    return Transport.UNKNOWN if url is None else _url_transport(url, client)


def _codex_headers(
    raw: Mapping[str, Any], headers: Mapping[str, str], pointer: str, outcome: ParseOutcome
) -> Mapping[str, str]:
    merged = dict(headers)
    merged.update(_string_map(raw.get("http_headers"), pointer + "/http_headers", outcome))
    from_env = _string_map(raw.get("env_http_headers"), pointer + "/env_http_headers", outcome)
    merged.update({header: "${" + variable + "}" for header, variable in from_env.items()})
    token = raw.get("bearer_token")
    if isinstance(token, str):
        merged.setdefault("Authorization", f"Bearer {token}")
    variable = raw.get("bearer_token_env_var")
    if isinstance(variable, str):
        merged.setdefault("Authorization", "Bearer ${" + variable + "}")
    return frozen_mapping(merged)


def normalize_entry(
    name: str,
    raw: Mapping[str, Any],
    source: ConfigSource,
    pointer: str,
    outcome: ParseOutcome,
    *,
    force_disabled: bool = False,
) -> ServerEntry:
    command = raw.get("command")
    args = _string_tuple(raw.get("args"), pointer + "/args", outcome)
    wrapped = unwrap(command if isinstance(command, str) else None, args)
    if wrapped is not None:
        command, args = wrapped.command, wrapped.args
        raw = {**raw, "command": command, "args": list(args)}
    url = next((raw[key] for key in URL_KEYS if isinstance(raw.get(key), str)), None)
    cwd = raw.get("cwd")
    enabled = raw.get("disabled") is not True and raw.get("enabled") is not False
    headers = _string_map(raw.get("headers"), pointer + "/headers", outcome)
    if source.client is Client.CODEX:
        headers = _codex_headers(raw, headers, pointer, outcome)
    return ServerEntry(
        name=name,
        source=source,
        pointer=pointer,
        transport=infer_transport(raw, source.client),
        command=command if isinstance(command, str) else None,
        args=args,
        env=_string_map(raw.get("env"), pointer + "/env", outcome),
        url=url,
        headers=headers,
        cwd=cwd if isinstance(cwd, str) else None,
        enabled=enabled and not force_disabled,
        raw=frozen_mapping(raw),
        shielded=wrapped is not None,
        shield_launcher=wrapped.launcher if wrapped is not None else (),
    )


def parse_server_map(
    value: Any,
    source: ConfigSource,
    base_pointer: str,
    outcome: ParseOutcome,
    disabled_names: frozenset[str] = frozenset(),
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        outcome.warn("not_an_object", base_pointer)
        return
    for name, raw in value.items():
        pointer = base_pointer + json_pointer(name)
        if not isinstance(raw, dict):
            outcome.warn("invalid_entry", pointer)
            continue
        if depth_exceeds(raw):
            outcome.warn("too_deep", pointer)
            continue
        outcome.servers.append(
            normalize_entry(
                name, raw, source, pointer, outcome, force_disabled=name in disabled_names
            )
        )


def project_key(path: Path) -> str:
    return os.path.normcase(str(path.absolute()))


def _parse_claude_code_state(
    location: ConfigLocation, document: dict[str, Any], outcome: ParseOutcome
) -> None:
    parse_server_map(document.get("mcpServers"), location.source, "/mcpServers", outcome)
    projects = document.get("projects")
    if projects is None:
        return
    if not isinstance(projects, dict):
        outcome.warn("not_an_object", "/projects")
        return
    for project_path, state in projects.items():
        if not isinstance(state, dict):
            continue
        project = Path(project_path)
        outcome.projects.append(project)
        source = ConfigSource(location.client, Scope.LOCAL, location.path, project)
        parse_server_map(
            state.get("mcpServers"),
            source,
            json_pointer("projects", project_path, "mcpServers"),
            outcome,
        )
        disabled = state.get("disabledMcpjsonServers")
        if isinstance(disabled, list):
            names = frozenset(item for item in disabled if isinstance(item, str))
            outcome.disabled_project_servers[project_key(project)] = names


def _parse_extension_manifest(
    location: ConfigLocation,
    document: dict[str, Any],
    outcome: ParseOutcome,
    extension_enabled: bool,
) -> None:
    server = document.get("server")
    config = server.get("mcp_config") if isinstance(server, dict) else None
    if not isinstance(config, dict):
        outcome.warn("missing_mcp_config", "/server/mcp_config")
        return
    declared_name = document.get("name")
    root_name = location.root.name if location.root else location.path.parent.name
    name = declared_name if isinstance(declared_name, str) and declared_name else root_name
    outcome.servers.append(
        normalize_entry(
            name,
            config,
            location.source,
            "/server/mcp_config",
            outcome,
            force_disabled=not extension_enabled,
        )
    )


def _resolve_inside(root: Path, reference: str) -> Path | None:
    if is_network_path(reference):
        return None
    try:
        candidate = (root / reference).resolve()
        base = root.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if candidate.is_relative_to(base):
        return candidate
    return None


def _parse_plugin_manifest(
    location: ConfigLocation, document: dict[str, Any], outcome: ParseOutcome
) -> None:
    servers = document.get("mcpServers")
    if servers is None:
        return
    if isinstance(servers, dict):
        parse_server_map(servers, location.source, "/mcpServers", outcome)
        return
    references = [servers] if isinstance(servers, str) else servers
    if not isinstance(references, list):
        outcome.warn("not_an_object", "/mcpServers")
        return
    root = location.root or location.path.parent
    default_file = (root / ".mcp.json").resolve()
    for reference in references:
        if not isinstance(reference, str):
            outcome.warn("invalid_reference", "/mcpServers")
            continue
        resolved = _resolve_inside(root, reference)
        if resolved is None:
            outcome.warn("reference_outside_root", reference)
            continue
        if resolved != default_file:
            outcome.references.append(resolved)


def parse_document(
    location: ConfigLocation,
    document: Any,
    outcome: ParseOutcome,
    *,
    disabled_names: frozenset[str] = frozenset(),
    extension_enabled: bool = True,
) -> None:
    if not isinstance(document, dict):
        outcome.warn("not_an_object", "/")
        return
    source = location.source
    match location.format:
        case ConfigFormat.MCP_SERVERS:
            parse_server_map(
                document.get("mcpServers"), source, "/mcpServers", outcome, disabled_names
            )
        case ConfigFormat.VSCODE:
            parse_server_map(document.get("servers"), source, "/servers", outcome)
        case ConfigFormat.VSCODE_SETTINGS:
            mcp = document.get("mcp")
            if isinstance(mcp, dict):
                parse_server_map(mcp.get("servers"), source, "/mcp/servers", outcome)
        case ConfigFormat.CLAUDE_CODE_STATE:
            _parse_claude_code_state(location, document, outcome)
        case ConfigFormat.CODEX_TOML:
            parse_server_map(document.get("mcp_servers"), source, "/mcp_servers", outcome)
        case ConfigFormat.EXTENSION_MANIFEST:
            _parse_extension_manifest(location, document, outcome, extension_enabled)
        case ConfigFormat.PLUGIN_MANIFEST:
            _parse_plugin_manifest(location, document, outcome)
        case ConfigFormat.PLUGIN_REFERENCE:
            if "mcpServers" in document:
                parse_server_map(document["mcpServers"], source, "/mcpServers", outcome)
            else:
                parse_server_map(document, source, "", outcome)
