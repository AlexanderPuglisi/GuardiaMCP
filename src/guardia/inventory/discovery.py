from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from guardia.inventory.environment import HostEnvironment
from guardia.inventory.locations import (
    ConfigFormat,
    ConfigLocation,
    project_locations,
    user_locations,
)
from guardia.inventory.parsers import ParseOutcome, parse_document, project_key
from guardia.inventory.skills import discover_skills
from guardia.locate import json_lines, toml_table_lines
from guardia.model import (
    Client,
    Inventory,
    Scope,
    ServerEntry,
    SourceRecord,
    SourceStatus,
    frozen_mapping,
)
from guardia.safeio import (
    ParsedDocument,
    ReadErrorCode,
    SafeReadError,
    decode_text,
    is_network_path,
    parse_json,
    parse_toml,
    read_bytes,
)
from guardia.shield.windows import remote_drive

MAX_SETTINGS_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 128 * 1024 * 1024
SERVER_CONTAINERS = frozenset(
    {"/mcpServers", "/servers", "/mcp", "/mcp_servers", "/inputs", "/server", "/context_servers"}
)


@dataclass(frozen=True, slots=True)
class DiscoveryOptions:
    project_dirs: tuple[Path, ...] = ()
    auto_projects: bool = True
    max_file_bytes: int = MAX_CONFIG_BYTES
    max_projects: int = 1000
    skills: bool = True


@dataclass(slots=True)
class _DiscoveryState:
    options: DiscoveryOptions
    servers: list[ServerEntry] = field(default_factory=list)
    records: list[SourceRecord] = field(default_factory=list)
    projects: list[Path] = field(default_factory=list)
    disabled_project_servers: dict[str, frozenset[str]] = field(default_factory=dict)
    seen: set[str] = field(default_factory=set)

    def load(self, location: ConfigLocation) -> ParsedDocument:
        text = decode_text(read_bytes(location.path, self.options.max_file_bytes))
        if location.format is ConfigFormat.CODEX_TOML:
            return parse_toml(text)
        if not text.strip():
            return ParsedDocument({}, text=text)
        return parse_json(text, jsonc=location.jsonc)

    def process(
        self, location: ConfigLocation, disabled_names: frozenset[str] = frozenset()
    ) -> None:
        key = project_key(location.path)
        if key in self.seen:
            return
        self.seen.add(key)
        try:
            parsed = self.load(location)
        except SafeReadError as exc:
            status = (
                SourceStatus.MISSING if exc.code is ReadErrorCode.MISSING else SourceStatus.ERROR
            )
            error_code = None if status is SourceStatus.MISSING else exc.code.value
            self.records.append(SourceRecord(location.source, status, error_code, exc.detail))
            return
        outcome = ParseOutcome()
        parse_document(
            location,
            parsed.value,
            outcome,
            disabled_names=disabled_names,
            extension_enabled=self.extension_enabled(location),
        )
        if location.disabled:
            outcome.servers = [replace(server, enabled=False) for server in outcome.servers]
        containers = {*SERVER_CONTAINERS, *(s.pointer.rsplit("/", 1)[0] for s in outcome.servers)}
        for duplicate in parsed.duplicate_keys:
            if _inside(duplicate, containers):
                outcome.warn("duplicate_key", duplicate)
        self.servers.extend(attach_lines(location, parsed, outcome.servers))
        self.projects.extend(outcome.projects)
        self.disabled_project_servers.update(outcome.disabled_project_servers)
        self.records.append(
            SourceRecord(
                location.source,
                SourceStatus.LOADED,
                server_count=len(outcome.servers),
                warnings=tuple(outcome.warnings),
            )
        )
        for reference in outcome.references:
            self.process(
                ConfigLocation(
                    location.client,
                    Scope.PLUGIN,
                    reference,
                    ConfigFormat.PLUGIN_REFERENCE,
                    root=location.root,
                    disabled=location.disabled,
                )
            )

    def extension_enabled(self, location: ConfigLocation) -> bool:
        if location.format is not ConfigFormat.EXTENSION_MANIFEST or location.root is None:
            return True
        settings = (
            location.root.parent.parent
            / "Claude Extensions Settings"
            / f"{location.root.name}.json"
        )
        try:
            document = parse_json(decode_text(read_bytes(settings, MAX_SETTINGS_BYTES))).value
        except SafeReadError:
            return True
        return not (isinstance(document, dict) and document.get("isEnabled") is False)


def attach_lines(
    location: ConfigLocation, parsed: ParsedDocument, servers: list[ServerEntry]
) -> list[ServerEntry]:
    if not servers:
        return servers
    if location.format is ConfigFormat.CODEX_TOML:
        all_lines = toml_table_lines(parsed.text)
    else:
        all_lines = json_lines(parsed.text)
    result = []
    for server in servers:
        prefix = server.pointer + "/"
        subset = {
            pointer: line
            for pointer, line in all_lines.items()
            if pointer == server.pointer or pointer.startswith(prefix)
        }
        if server.shielded:
            subset = _unwrapped_lines(server, parsed.value, subset)
        result.append(replace(server, lines=frozen_mapping(subset)))
    return result


def _entry_at(document: Any, pointer: str) -> Any:
    node = document
    for part in pointer.split("/")[1:]:
        if not isinstance(node, dict):
            return None
        node = node.get(part.replace("~1", "/").replace("~0", "~"))
    return node


def _unwrapped_lines(server: ServerEntry, document: Any, lines: dict[str, int]) -> dict[str, int]:
    entry = _entry_at(document, server.pointer)
    args = entry.get("args") if isinstance(entry, dict) else None
    if not isinstance(args, list):
        return lines
    start = len(args) - len(server.args) - 1
    if start < 0:
        return lines
    base = server.pointer
    mapped = {
        pointer: line for pointer, line in lines.items() if not pointer.startswith(f"{base}/args/")
    }
    command = lines.get(f"{base}/args/{start}")
    if command is not None:
        mapped[f"{base}/command"] = command
    for index in range(len(server.args)):
        line = lines.get(f"{base}/args/{start + 1 + index}")
        if line is not None:
            mapped[f"{base}/args/{index}"] = line
    return mapped


def _inside(pointer: str, containers: set[str]) -> bool:
    return any(
        pointer == container
        or pointer.startswith(container + "/")
        or container.startswith(pointer + "/")
        for container in containers
    )


def _existing_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def remote_path(path: Path) -> bool:
    if is_network_path(str(path)):
        return True
    drive = path.drive
    return len(drive) == 2 and drive[1] == ":" and remote_drive(drive)


def _collect_projects(
    env: HostEnvironment, options: DiscoveryOptions, discovered: list[Path]
) -> list[Path]:
    chosen = [(candidate, True) for candidate in options.project_dirs]
    if options.auto_projects:
        chosen.extend((candidate, False) for candidate in discovered)
        chosen.append((env.cwd, True))
    result: list[Path] = []
    seen: set[str] = set()
    for candidate, explicit in chosen:
        project = candidate if candidate.is_absolute() else env.cwd / candidate
        key = project_key(project)
        if key in seen or (not explicit and remote_path(project)):
            continue
        if not _existing_dir(project):
            continue
        seen.add(key)
        result.append(project)
        if len(result) >= options.max_projects:
            break
    return result


def discover(env: HostEnvironment, options: DiscoveryOptions | None = None) -> Inventory:
    options = options or DiscoveryOptions()
    state = _DiscoveryState(options)
    for location in user_locations(env):
        state.process(location)
    projects = _collect_projects(env, options, state.projects)
    for project in projects:
        disabled = state.disabled_project_servers.get(project_key(project), frozenset())
        for location in project_locations(project):
            claude_project_file = (
                location.client is Client.CLAUDE_CODE and location.scope is Scope.PROJECT
            )
            state.process(location, disabled if claude_project_file else frozenset())
    skills = discover_skills(env, projects) if options.skills else ()
    return Inventory(tuple(state.servers), tuple(state.records), skills=skills)
