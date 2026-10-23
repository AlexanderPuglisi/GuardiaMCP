from __future__ import annotations

import enum
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from guardia.inventory.environment import HostEnvironment
from guardia.model import Client, ConfigSource, Scope

MAX_DIR_ENTRIES = 2000
MAX_WALKED_DIRS = 5000
PLUGIN_WALK_DEPTH = 6
PRUNED_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages"})
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

    @property
    def source(self) -> ConfigSource:
        return ConfigSource(self.client, self.scope, self.path, self.project)


def child_dirs(path: Path, limit: int = MAX_DIR_ENTRIES) -> list[Path]:
    try:
        entries = sorted(path.iterdir())[:limit]
    except OSError:
        return []
    result = []
    for entry in entries:
        try:
            if entry.is_dir() and not entry.is_symlink():
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
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNED_DIRS)
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
    locations.append(
        ConfigLocation(
            Client.CLAUDE_CODE,
            Scope.USER,
            env.home / ".claude.json",
            ConfigFormat.CLAUDE_CODE_STATE,
        )
    )
    locations.append(
        ConfigLocation(
            Client.CLAUDE_CODE,
            Scope.MANAGED,
            env.managed_dir / "managed-mcp.json",
            ConfigFormat.MCP_SERVERS,
        )
    )
    code_plugins = env.home / ".claude" / "plugins" / "cache"
    locations.extend(plugin_locations(code_plugins, Client.CLAUDE_CODE))
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
    locations.append(
        ConfigLocation(
            Client.CODEX, Scope.USER, env.home / ".codex" / "config.toml", ConfigFormat.CODEX_TOML
        )
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


def plugin_locations(base: Path, client: Client) -> list[ConfigLocation]:
    try:
        if not base.is_dir():
            return []
    except OSError:
        return []
    locations: list[ConfigLocation] = []
    for directory, filenames in walk_limited(base, PLUGIN_WALK_DEPTH):
        if ".mcp.json" in filenames:
            locations.append(
                ConfigLocation(
                    client,
                    Scope.PLUGIN,
                    directory / ".mcp.json",
                    ConfigFormat.MCP_SERVERS,
                    root=directory,
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
                )
            )
    return locations


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
