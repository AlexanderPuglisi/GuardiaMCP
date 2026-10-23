from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from guardia.analysis import analyze
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.inventory.parsers import infer_transport
from guardia.model import Client, Inventory, Scope, ServerEntry, SourceStatus, Transport
from tests.conftest import WriteJson, WriteText


def by_name(inventory: Inventory) -> dict[str, ServerEntry]:
    return {server.name: server for server in inventory.servers}


def run(env: HostEnvironment, **options: Any) -> Inventory:
    return discover(env, DiscoveryOptions(**options))


def test_empty_machine_has_no_servers_and_no_errors(env: HostEnvironment) -> None:
    inventory = run(env)
    assert inventory.servers == ()
    assert inventory.failed_sources == ()
    assert all(r.status is SourceStatus.MISSING for r in inventory.sources)


def test_claude_desktop_config(env: HostEnvironment, write_json: WriteJson) -> None:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\docs"],
                    "env": {"LOG_LEVEL": "info"},
                },
                "remote": {"url": "https://mcp.example.com/mcp"},
            }
        },
    )
    servers = by_name(run(env))
    filesystem = servers["filesystem"]
    assert filesystem.source.client is Client.CLAUDE_DESKTOP
    assert filesystem.source.scope is Scope.USER
    assert filesystem.transport is Transport.STDIO
    assert filesystem.args == ("-y", "@modelcontextprotocol/server-filesystem", "C:\\docs")
    assert filesystem.env == {"LOG_LEVEL": "info"}
    assert filesystem.pointer == "/mcpServers/filesystem"
    assert servers["remote"].transport is Transport.HTTP


def test_claude_desktop_store_install(env: HostEnvironment, write_json: WriteJson) -> None:
    package = env.local_app_data / "Packages" / "Claude_pzs8sxrjxfjjc"
    write_json(
        package / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {"store-server": {"command": "uvx", "args": ["store-mcp"]}}},
    )
    assert "store-server" in by_name(run(env))


def test_claude_desktop_data_profile(env: HostEnvironment, write_json: WriteJson) -> None:
    profile = env.local_app_data / "Claude-Data" / "claude_abc123"
    write_json(
        profile / "claude_desktop_config.json",
        {"mcpServers": {"profile-server": {"command": "npx", "args": ["p"]}}},
    )
    extension = profile / "Claude Extensions" / "local.mcpb.vendor.tool"
    write_json(
        extension / "manifest.json",
        {"name": "vendor-tool", "server": {"mcp_config": {"command": "tool.exe"}}},
    )
    write_json(
        profile / "Claude Extensions Settings" / "local.mcpb.vendor.tool.json", {"isEnabled": False}
    )
    plugin = profile / "rpm" / "org" / "account" / "plugin_01ABC"
    write_json(plugin / ".mcp.json", {"mcpServers": {"desktop-plugin": {"command": "dp"}}})
    write_json(plugin / ".claude-plugin" / "plugin.json", {"name": "desktop-plugin"})
    write_json(
        env.local_app_data / "Claude-Data" / "not-a-profile" / "claude_desktop_config.json",
        {"mcpServers": {"ignored": {"command": "i"}}},
    )
    servers = by_name(run(env))
    assert servers["profile-server"].source.client is Client.CLAUDE_DESKTOP
    assert servers["vendor-tool"].enabled is False
    assert servers["desktop-plugin"].source.client is Client.CLAUDE_DESKTOP
    assert servers["desktop-plugin"].source.scope is Scope.PLUGIN
    assert "ignored" not in servers


def test_claude_desktop_extension_respects_disabled_setting(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    claude_dir = env.app_config / "Claude"
    for name, enabled in (("ext.on", True), ("ext.off", False)):
        write_json(
            claude_dir / "Claude Extensions" / name / "manifest.json",
            {
                "name": name,
                "server": {
                    "type": "node",
                    "entry_point": "server/index.js",
                    "mcp_config": {"command": "node", "args": ["${__dirname}/server/index.js"]},
                },
            },
        )
        write_json(
            claude_dir / "Claude Extensions Settings" / f"{name}.json", {"isEnabled": enabled}
        )
    servers = by_name(run(env))
    assert servers["ext.on"].enabled is True
    assert servers["ext.off"].enabled is False
    assert servers["ext.on"].source.scope is Scope.EXTENSION
    assert servers["ext.on"].pointer == "/server/mcp_config"


def test_claude_code_user_local_and_project_scopes(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    project = env.home / "code" / "app"
    project.mkdir(parents=True)
    write_json(
        env.home / ".claude.json",
        {
            "numStartups": 3,
            "mcpServers": {"user-server": {"type": "stdio", "command": "node", "args": ["u.js"]}},
            "projects": {
                str(project): {
                    "mcpServers": {
                        "local-server": {"type": "http", "url": "https://l.example/mcp"}
                    },
                    "disabledMcpjsonServers": ["rejected"],
                },
                str(env.home / "missing-project"): {"mcpServers": {}},
            },
        },
    )
    write_json(
        project / ".mcp.json",
        {
            "mcpServers": {
                "shared": {"command": "npx", "args": ["shared-mcp"]},
                "rejected": {"command": "npx", "args": ["bad-mcp"]},
            }
        },
    )
    servers = by_name(run(env))
    assert servers["user-server"].source.scope is Scope.USER
    assert servers["local-server"].source.scope is Scope.LOCAL
    assert servers["local-server"].source.project == project
    assert servers["shared"].source.scope is Scope.PROJECT
    assert servers["shared"].enabled is True
    assert servers["rejected"].enabled is False


def test_managed_configuration(env: HostEnvironment, write_json: WriteJson) -> None:
    write_json(
        env.managed_dir / "managed-mcp.json",
        {"mcpServers": {"company": {"type": "http", "url": "https://internal.example.com/mcp"}}},
    )
    company = by_name(run(env))["company"]
    assert company.source.scope is Scope.MANAGED
    assert company.source.client is Client.CLAUDE_CODE


def test_other_clients(env: HostEnvironment, write_json: WriteJson, write_text: WriteText) -> None:
    write_json(
        env.home / ".cursor" / "mcp.json",
        {"mcpServers": {"cursor-off": {"command": "npx", "args": ["c"], "disabled": True}}},
    )
    write_json(
        env.home / ".codeium" / "windsurf" / "mcp_config.json",
        {"mcpServers": {"windsurf-remote": {"serverUrl": "https://w.example/sse"}}},
    )
    write_json(
        env.home / ".copilot" / "mcp-config.json",
        {"mcpServers": {"copilot-server": {"command": "copilot-mcp"}}},
    )
    write_text(
        env.home / ".gemini" / "settings.json",
        '{\n  // Gemini allows comments\n  "mcpServers": {\n'
        '    "gemini-sse": {"url": "https://g.example/events"},\n'
        '    "gemini-http": {"httpUrl": "https://g.example/mcp"},\n  },\n}\n',
    )
    servers = by_name(run(env))
    assert servers["cursor-off"].enabled is False
    assert servers["cursor-off"].source.client is Client.CURSOR
    assert servers["windsurf-remote"].transport is Transport.SSE
    assert servers["windsurf-remote"].url == "https://w.example/sse"
    assert servers["copilot-server"].source.client is Client.COPILOT_CLI
    assert servers["gemini-sse"].transport is Transport.SSE
    assert servers["gemini-http"].transport is Transport.HTTP


def test_vscode_user_profiles_settings_and_workspace(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    user_dir = env.app_config / "Code" / "User"
    write_text(
        user_dir / "mcp.json",
        '{\n  // comment\n  "servers": {"vs-user": {"type": "stdio", "command": "node",},},\n'
        '  "inputs": []\n}',
    )
    write_json(
        user_dir / "profiles" / "abc123" / "mcp.json", {"servers": {"vs-profile": {"command": "x"}}}
    )
    write_json(user_dir / "settings.json", {"mcp": {"servers": {"vs-legacy": {"command": "y"}}}})
    write_json(
        env.cwd / ".vscode" / "mcp.json",
        {"servers": {"vs-workspace": {"type": "sse", "url": "http://localhost:3000/sse"}}},
    )
    servers = by_name(run(env))
    assert {"vs-user", "vs-profile", "vs-legacy", "vs-workspace"} <= set(servers)
    assert servers["vs-workspace"].source.scope is Scope.PROJECT
    assert servers["vs-workspace"].source.project == env.cwd
    assert servers["vs-workspace"].transport is Transport.SSE


def test_codex_toml(env: HostEnvironment, write_text: WriteText) -> None:
    write_text(
        env.home / ".codex" / "config.toml",
        'model = "x"\n\n[mcp_servers.docs]\ncommand = "npx"\nargs = ["-y", "docs-mcp"]\n'
        'env = { DOCS_TOKEN = "t" }\n\n'
        '[mcp_servers.off]\nurl = "https://o.example/mcp"\nenabled = false\n',
    )
    servers = by_name(run(env))
    assert servers["docs"].source.client is Client.CODEX
    assert servers["docs"].args == ("-y", "docs-mcp")
    assert servers["docs"].pointer == "/mcp_servers/docs"
    assert servers["off"].enabled is False


def test_hostile_values_in_configs_do_not_stop_the_scan(
    env: HostEnvironment, write_text: WriteText
) -> None:
    write_text(
        env.home / ".codex" / "config.toml",
        '[mcp_servers.dated]\ncommand = "npx"\nupdated = 2024-01-01\n',
    )
    write_text(
        env.cwd / ".mcp.json",
        '{"mcpServers": {"huge": {"command": "node", "args": [' + "9" * 5000 + "]}}}",
    )
    report = analyze(env)
    assert "dated" in {server.name for server in report.inventory.servers}
    assert "G12-006" in {finding.rule_id for finding in report.findings}


def test_claude_code_plugins(env: HostEnvironment, write_json: WriteJson) -> None:
    plugin = env.home / ".claude" / "plugins" / "cache" / "market" / "tools" / "1.0.0"
    write_json(plugin / ".mcp.json", {"mcpServers": {"plugin-default": {"command": "p1"}}})
    write_json(
        plugin / ".claude-plugin" / "plugin.json",
        {"name": "tools", "mcpServers": ["./.mcp.json", "./extra.json", "../../../../escape.json"]},
    )
    write_json(plugin / "extra.json", {"plugin-extra": {"command": "p2"}})
    write_json(
        env.home / ".claude" / "plugins" / "escape.json", {"mcpServers": {"evil": {"command": "e"}}}
    )
    inline = env.home / ".claude" / "plugins" / "cache" / "market" / "inline" / "2.0.0"
    write_json(
        inline / ".claude-plugin" / "plugin.json",
        {"name": "inline", "mcpServers": {"plugin-inline": {"command": "p3"}}},
    )
    inventory = run(env)
    servers = by_name(inventory)
    assert {"plugin-default", "plugin-extra", "plugin-inline"} <= set(servers)
    assert "evil" not in servers
    assert all(s.source.scope is Scope.PLUGIN for s in inventory.servers)
    assert [s.name for s in inventory.servers].count("plugin-default") == 1
    warnings = [w for r in inventory.sources for w in r.warnings]
    assert any(w.startswith("reference_outside_root:") for w in warnings)


def test_plugin_walk_skips_node_modules(env: HostEnvironment, write_json: WriteJson) -> None:
    base = env.home / ".claude" / "plugins" / "cache" / "m" / "p" / "1"
    write_json(
        base / "node_modules" / "dep" / ".mcp.json", {"mcpServers": {"hidden": {"command": "h"}}}
    )
    assert "hidden" not in by_name(run(env))


def test_malformed_and_oversized_files_are_reported(
    env: HostEnvironment, write_text: WriteText, write_json: WriteJson
) -> None:
    write_text(env.home / ".cursor" / "mcp.json", '{"mcpServers": {"broken": ')
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {"big": {"command": "x", "args": ["y" * 4000]}}},
    )
    inventory = run(env, max_file_bytes=2000)
    errors = {r.source.client: r for r in inventory.failed_sources}
    assert errors[Client.CURSOR].error_code == "parse"
    assert errors[Client.CLAUDE_DESKTOP].error_code == "too_large"
    assert inventory.servers == ()


def test_invalid_entries_and_duplicates_produce_warnings(
    env: HostEnvironment, write_text: WriteText
) -> None:
    write_text(
        env.home / ".cursor" / "mcp.json",
        '{"mcpServers": {"good": {"command": "a", "args": "not-a-list"}, "bad": "text",'
        ' "dup": {"command": "first"}, "dup": {"command": "second"}}}',
    )
    inventory = run(env)
    servers = by_name(inventory)
    assert servers["good"].args == ()
    assert servers["dup"].command == "second"
    assert "bad" not in servers
    warnings = inventory.loaded_sources[0].warnings
    assert "invalid_args:/mcpServers/good/args" in warnings
    assert "invalid_entry:/mcpServers/bad" in warnings
    assert "duplicate_key:dup" in warnings


def test_utf16_file_written_by_old_powershell_is_read(env: HostEnvironment) -> None:
    path = env.home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_bytes('{"mcpServers": {"wide": {"command": "w"}}}'.encode("utf-16"))
    assert "wide" in by_name(run(env))


def test_explicit_project_and_disabling_auto_projects(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    explicit = env.home / "elsewhere"
    write_json(explicit / ".cursor" / "mcp.json", {"mcpServers": {"explicit": {"command": "e"}}})
    write_json(env.cwd / ".mcp.json", {"mcpServers": {"from-cwd": {"command": "c"}}})
    assert {"explicit", "from-cwd"} <= set(by_name(run(env, project_dirs=(explicit,))))
    only_explicit = by_name(run(env, project_dirs=(explicit,), auto_projects=False))
    assert "explicit" in only_explicit
    assert "from-cwd" not in only_explicit


def test_same_file_is_read_once(env: HostEnvironment, write_json: WriteJson) -> None:
    write_json(env.cwd / ".mcp.json", {"mcpServers": {"once": {"command": "o"}}})
    inventory = run(env, project_dirs=(env.cwd, env.cwd))
    assert [s.name for s in inventory.servers] == ["once"]


def test_discovery_never_modifies_files(env: HostEnvironment, write_json: WriteJson) -> None:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {"a": {"command": "x"}}},
    )
    write_json(env.home / ".claude.json", {"mcpServers": {"b": {"command": "y"}}})
    write_json(env.cwd / ".mcp.json", {"mcpServers": {"c": {"command": "z"}}})
    root = env.home.parent

    def snapshot() -> dict[Path, tuple[str, int]]:
        return {
            path: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
            for path in root.rglob("*")
            if path.is_file()
        }

    before = snapshot()
    run(env)
    assert snapshot() == before


@pytest.mark.parametrize(
    ("raw", "client", "expected"),
    [
        ({"command": "npx"}, Client.CLAUDE_CODE, Transport.STDIO),
        ({"type": "streamable-http", "url": "https://x"}, Client.CLAUDE_CODE, Transport.HTTP),
        ({"type": "SSE", "url": "https://x"}, Client.CLAUDE_CODE, Transport.SSE),
        ({"type": "carrier-pigeon"}, Client.CLAUDE_CODE, Transport.UNKNOWN),
        ({"url": "wss://x/ws"}, Client.CURSOR, Transport.WEBSOCKET),
        ({"url": "https://x/sse"}, Client.CURSOR, Transport.SSE),
        ({"url": "https://x/mcp"}, Client.CURSOR, Transport.HTTP),
        ({"url": "https://x/mcp"}, Client.GEMINI_CLI, Transport.SSE),
        ({"httpUrl": "https://x/mcp"}, Client.GEMINI_CLI, Transport.HTTP),
        ({}, Client.CURSOR, Transport.UNKNOWN),
    ],
)
def test_transport_inference(raw: dict[str, str], client: Client, expected: Transport) -> None:
    assert infer_transport(raw, client) is expected
