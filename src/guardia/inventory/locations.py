from __future__ import annotations

import enum
import os
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from guardia.inventory.environment import HostEnvironment
from guardia.model import Client, ConfigSource, Scope
from guardia.safeio import SafeReadError, parse_json, read_text

MAX_DIR_ENTRIES = 2000
MAX_WALKED_DIRS = 5000
MAX_SETTINGS_BYTES = 1024 * 1024
PLUGIN_WALK_DEPTH = 6
PRUNED_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages"})
EXAMPLE_DIRS = frozenset(
    {
        "example",
        "examples",
        "demo",
        "demos",
        "doc",
        "docs",
        "test",
        "tests",
        "__tests__",
        "fixtures",
        "sample",
        "samples",
        "template",
        "templates",
    }
)
VERSION_NAME = re.compile(r"^(?:v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?|[0-9a-f]{7,40})$")
VSCODE_FLAVOURS = ("Code", "Code - Insiders", "VSCodium")


class ConfigFormat(enum.StrEnum):
    MCP_SERVERS = "mcp-servers"
    VSCODE = "vscode"
    VSCODE_SETTINGS = "vscode-settings"
    CLAUDE_CODE_STATE = "claude-code-state"
    CODEX_TOML = "codex-toml"
    EXTENSION_MANIFEST = "extension-manifest"
    PLUGIN_MANIFEST = "plugin-manifest"
    PLUGIN_REFERENCE = "plugin-reference"


@dataclass(frozen=True, slots=True)
class ConfigLocation:
    client: Client
    scope: Scope
    path: Path
    format: ConfigFormat
    jsonc: bool = False
    project: Path | None = None
    root: Path | None = None
    disabled: bool = False

    @property
    def source(self) -> ConfigSource:
        return ConfigSource(self.client, self.scope, self.path, self.project)


def linked(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def real_dirs(dirpath: str, names: Iterable[str]) -> list[str]:
    return [name for name in names if not (Path(dirpath) / name).is_junction()]


def child_dirs(path: Path, limit: int = MAX_DIR_ENTRIES) -> list[Path]:
    try:
        entries = sorted(path.iterdir())[:limit]
    except OSError:
        return []
    result = []
    for entry in entries:
        try:
            if entry.is_dir() and not linked(entry):
                result.append(entry)
        except OSError:
            continue
    return result


def walk_limited(
    base: Path, max_depth: int, max_dirs: int = MAX_WALKED_DIRS
) -> Iterator[tuple[Path, list[str]]]:
    for visited, (dirpath, dirnames, filenames) in enumerate(
        os.walk(base, followlinks=False), start=1
    ):
        if visited > max_dirs:
            return
        current = Path(dirpath)
        depth = len(current.relative_to(base).parts)
        dirnames[:] = sorted(d for d in real_dirs(dirpath, dirnames) if d not in PRUNED_DIRS)
        if depth >= max_depth:
            dirnames.clear()
        yield current, filenames


def claude_desktop_dirs(env: HostEnvironment) -> list[Path]:
    dirs = [env.app_config / "Claude"]
    dirs.extend(
        profile
        for profile in child_dirs(env.local_app_data / "Claude-Data")
        if profile.name.startswith("claude_")
    )
    if env.platform == "windows":
        dirs.extend(
            package / "LocalCache" / "Roaming" / "Claude"
            for package in child_dirs(env.local_app_data / "Packages")
            if package.name.startswith("Claude_")
        )
    return dirs


def user_locations(env: HostEnvironment) -> list[ConfigLocation]:
    locations: list[ConfigLocation] = []
    for claude_dir in claude_desktop_dirs(env):
        locations.append(
            ConfigLocation(
                Client.CLAUDE_DESKTOP,
                Scope.USER,
                claude_dir / "claude_desktop_config.json",
                ConfigFormat.MCP_SERVERS,
            )
        )
        for extension in child_dirs(claude_dir / "Claude Extensions"):
            locations.append(
                ConfigLocation(
                    Client.CLAUDE_DESKTOP,
                    Scope.EXTENSION,
                    extension / "manifest.json",
                    ConfigFormat.EXTENSION_MANIFEST,
                    root=extension,
                )
            )
        locations.extend(plugin_locations(claude_dir / "rpm", Client.CLAUDE_DESKTOP))
    locations.extend(
        ConfigLocation(Client.CLAUDE_CODE, Scope.USER, state, ConfigFormat.CLAUDE_CODE_STATE)
        for state in env.claude_state_files()
    )
    locations.append(
        ConfigLocation(
            Client.CLAUDE_CODE,
            Scope.MANAGED,
            env.managed_dir / "managed-mcp.json",
            ConfigFormat.MCP_SERVERS,
        )
    )
    enabled = enabled_plugins(env)
    for claude_dir in env.claude_dirs():
        locations.extend(
            plugin_locations(claude_dir / "plugins" / "cache", Client.CLAUDE_CODE, enabled)
        )
    locations.append(
        ConfigLocation(
            Client.CURSOR, Scope.USER, env.home / ".cursor" / "mcp.json", ConfigFormat.MCP_SERVERS
        )
    )
    for flavour in VSCODE_FLAVOURS:
        user_dir = env.app_config / flavour / "User"
        for profile_dir in (user_dir, *child_dirs(user_dir / "profiles")):
            locations.append(
                ConfigLocation(
                    Client.VSCODE,
                    Scope.USER,
                    profile_dir / "mcp.json",
                    ConfigFormat.VSCODE,
                    jsonc=True,
                )
            )
            locations.append(
                ConfigLocation(
                    Client.VSCODE,
                    Scope.USER,
                    profile_dir / "settings.json",
                    ConfigFormat.VSCODE_SETTINGS,
                    jsonc=True,
                )
            )
    locations.append(
        ConfigLocation(
            Client.WINDSURF,
            Scope.USER,
            env.home / ".codeium" / "windsurf" / "mcp_config.json",
            ConfigFormat.MCP_SERVERS,
        )
    )
    locations.append(
        ConfigLocation(
            Client.GEMINI_CLI,
            Scope.USER,
            env.home / ".gemini" / "settings.json",
            ConfigFormat.MCP_SERVERS,
            jsonc=True,
        )
    )
    locations.extend(
        ConfigLocation(
            Client.GEMINI_CLI,
            Scope.PLUGIN,
            extension / "gemini-extension.json",
            ConfigFormat.MCP_SERVERS,
            jsonc=True,
            root=extension,
        )
        for extension in child_dirs(env.home / ".gemini" / "extensions")
    )
    locations.extend(
        ConfigLocation(Client.CODEX, Scope.USER, codex / "config.toml", ConfigFormat.CODEX_TOML)
        for codex in env.codex_dirs()
    )
    locations.append(
        ConfigLocation(
            Client.COPILOT_CLI,
            Scope.USER,
            env.home / ".copilot" / "mcp-config.json",
            ConfigFormat.MCP_SERVERS,
        )
    )
    return locations


def enabled_plugins(env: HostEnvironment) -> dict[str, bool]:
    enabled: dict[str, bool] = {}
    for claude_dir in env.claude_dirs():
        try:
            document = parse_json(
                read_text(claude_dir / "settings.json", MAX_SETTINGS_BYTES), jsonc=True
            )
        except SafeReadError:
            continue
        plugins = document.value.get("enabledPlugins") if isinstance(document.value, dict) else None
        if isinstance(plugins, dict):
            enabled.update(
                {str(key): value for key, value in plugins.items() if isinstance(value, bool)}
            )
    return enabled


def _plugin_disabled(parts: tuple[str, ...], enabled: Mapping[str, bool]) -> bool:
    return len(parts) >= 2 and enabled.get(f"{parts[1]}@{parts[0]}") is False


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _newest_versions(base: Path, locations: list[ConfigLocation]) -> list[ConfigLocation]:
    kept: list[ConfigLocation] = []
    grouped: dict[tuple[str, str], dict[str, list[ConfigLocation]]] = {}
    for location in locations:
        parts = (location.root or location.path.parent).relative_to(base).parts
        if len(parts) >= 3 and VERSION_NAME.match(parts[2]):
            grouped.setdefault((parts[0], parts[1]), {}).setdefault(parts[2], []).append(location)
        else:
            kept.append(location)
    for (marketplace, plugin), versions in grouped.items():
        newest = max(versions, key=lambda name: _mtime(base / marketplace / plugin / name))
        kept.extend(versions[newest])
    return kept


def plugin_locations(
    base: Path, client: Client, enabled: Mapping[str, bool] | None = None
) -> list[ConfigLocation]:
    try:
        if not base.is_dir():
            return []
    except OSError:
        return []
    locations: list[ConfigLocation] = []
    for directory, filenames in walk_limited(base, PLUGIN_WALK_DEPTH):
        parts = directory.relative_to(base).parts
        if any(part.lower() in EXAMPLE_DIRS for part in parts):
            continue
        disabled = _plugin_disabled(parts, enabled or {})
        if ".mcp.json" in filenames:
            locations.append(
                ConfigLocation(
                    client,
                    Scope.PLUGIN,
                    directory / ".mcp.json",
                    ConfigFormat.MCP_SERVERS,
                    root=directory,
                    disabled=disabled,
                )
            )
        if directory.name == ".claude-plugin" and "plugin.json" in filenames:
            locations.append(
                ConfigLocation(
                    client,
                    Scope.PLUGIN,
                    directory / "plugin.json",
                    ConfigFormat.PLUGIN_MANIFEST,
                    root=directory.parent,
                    disabled=disabled,
                )
            )
    return _newest_versions(base, locations)


def project_locations(project: Path) -> list[ConfigLocation]:
    return [
        ConfigLocation(
            Client.CLAUDE_CODE,
            Scope.PROJECT,
            project / ".mcp.json",
            ConfigFormat.MCP_SERVERS,
            project=project,
        ),
        ConfigLocation(
            Client.CURSOR,
            Scope.PROJECT,
            project / ".cursor" / "mcp.json",
            ConfigFormat.MCP_SERVERS,
            project=project,
        ),
        ConfigLocation(
            Client.VSCODE,
            Scope.PROJECT,
            project / ".vscode" / "mcp.json",
            ConfigFormat.VSCODE,
            jsonc=True,
            project=project,
        ),
        ConfigLocation(
            Client.VSCODE,
            Scope.PROJECT,
            project / ".vscode" / "settings.json",
            ConfigFormat.VSCODE_SETTINGS,
            jsonc=True,
            project=project,
        ),
        ConfigLocation(
            Client.GEMINI_CLI,
            Scope.PROJECT,
            project / ".gemini" / "settings.json",
            ConfigFormat.MCP_SERVERS,
            jsonc=True,
            project=project,
        ),
    ]
