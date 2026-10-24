from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import guardia.analysis as analysis_module
from guardia.analysis import AnalysisOptions, analyze
from guardia.extract import collect_tools
from guardia.extract.js_source import decode_string
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.inventory import discovery as discovery_module
from guardia.inventory.discovery import remote_path
from guardia.model import Client, Scope, ServerEntry, Transport
from guardia.scanner.engine import ServerReport
from guardia.shield.wrapping import launcher, wrap
from tests.conftest import WriteJson, WriteText

JS_SERVER = """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "weather", version: "1.0.0" });
server.tool("forecast", "Gets the weather forecast for a city.", {}, async () => ({ content: [] }));
"""
PY_SERVER = '''from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")


@mcp.tool()
def forecast(city: str) -> str:
    """Gets the weather forecast for a city."""
    return city
'''


def scan(env: HostEnvironment, *, tools: bool = True) -> dict[str, ServerReport]:
    report = analyze(env, AnalysisOptions(tools=tools))
    return {entry.server.name: entry for entry in report.servers}


def tool_names(report: ServerReport) -> list[str]:
    assert report.tools is not None
    return sorted(tool.name for tool in report.tools.tools)


def desktop(env: HostEnvironment) -> Path:
    return env.app_config / "Claude" / "claude_desktop_config.json"


def test_unicode_escapes_are_decoded_safely() -> None:
    assert decode_string("\\uD83D\\uDE80 Launch") == "\U0001f680 Launch"
    assert decode_string("bad \\udc00 half") == "bad \ufffd half"


def test_lone_surrogates_never_crash_the_scan(env: HostEnvironment, write_text: WriteText) -> None:
    write_text(
        env.cwd / ".vscode" / "mcp.json",
        '{"servers":{"helper":{"type":"stdio","command":"node","args":["tools/x.js","\\udc00"]}}}',
    )
    write_text(env.cwd / "tools" / "x.js", JS_SERVER.replace("Gets", "\\uD83D\\uDE80 \\udc00 Gets"))
    report = analyze(env, AnalysisOptions())
    helper = next(entry for entry in report.servers if entry.server.name == "helper")
    assert helper.tools is not None
    assert helper.tools.analyzed
    assert report.ledger is not None
    assert report.ledger.recorded
    analyze(env, AnalysisOptions())


def test_paths_with_spaces_are_analyzed(env: HostEnvironment, write_json: WriteJson) -> None:
    script = env.home / "Mario Rossi" / "mcp" / "weather" / "build" / "index.js"
    script.parent.mkdir(parents=True)
    script.write_text(JS_SERVER, encoding="utf-8")
    project = env.home / "OneDrive - Contoso" / "py server"
    project.mkdir(parents=True)
    (project / "server.py").write_text(PY_SERVER, encoding="utf-8")
    write_json(
        desktop(env),
        {
            "mcpServers": {
                "weather": {"command": "node", "args": [str(script)]},
                "pyweather": {
                    "command": "uv",
                    "args": ["--directory", str(project), "run", "server.py"],
                },
                "joined": {"command": "uv", "args": [f"--directory={project}", "run", "server.py"]},
            }
        },
    )
    reports = scan(env)
    assert tool_names(reports["weather"]) == ["forecast"]
    assert tool_names(reports["pyweather"]) == ["forecast"]
    assert tool_names(reports["joined"]) == ["forecast"]


def test_project_relative_servers_are_analyzed(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    write_text(env.cwd / "tools" / "mcp" / "server.js", JS_SERVER)
    write_json(
        env.cwd / ".mcp.json",
        {"mcpServers": {"repo-tool": {"command": "node", "args": ["tools/mcp/server.js"]}}},
    )
    write_json(
        env.cwd / ".cursor" / "mcp.json",
        {"mcpServers": {"cursor-tool": {"command": "node", "args": ["./tools/mcp/server.js"]}}},
    )
    write_json(
        env.cwd / ".vscode" / "mcp.json",
        {
            "servers": {
                "code-tool": {
                    "type": "stdio",
                    "command": "node",
                    "args": ["${workspaceFolder}/tools/mcp/server.js"],
                }
            }
        },
    )
    reports = scan(env)
    for name in ("repo-tool", "cursor-tool", "code-tool"):
        assert tool_names(reports[name]) == ["forecast"], name


def test_global_npm_and_uv_tool_installs_are_found(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    npm = env.app_config / "npm"
    write_text(
        npm / "weather-mcp.cmd",
        '@ECHO off\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  '
        '"%dp0%\\node_modules\\@acme\\weather-mcp\\build\\index.js" %*\r\n',
    )
    write_text(npm / "node_modules" / "@acme" / "weather-mcp" / "build" / "index.js", JS_SERVER)
    tool_env = env.app_config / "uv" / "tools" / "pyweather"
    write_text(tool_env / "Scripts" / "pyweather-mcp.exe", "")
    site = tool_env / "Lib" / "site-packages"
    write_text(site / "pyweather_mcp" / "__init__.py", "")
    write_text(site / "pyweather_mcp" / "server.py", PY_SERVER)
    write_text(
        site / "pyweather_mcp-1.0.0.dist-info" / "entry_points.txt",
        "[console_scripts]\npyweather-mcp = pyweather_mcp.server:main\n",
    )
    venv = env.home / "proj" / ".venv"
    write_text(venv / "Lib" / "site-packages" / "localpkg" / "__init__.py", PY_SERVER)
    write_json(
        desktop(env),
        {
            "mcpServers": {
                "npm-global": {"command": "weather-mcp", "args": []},
                "uv-tool": {"command": str(tool_env / "Scripts" / "pyweather-mcp.exe")},
                "module": {
                    "command": str(venv / "Scripts" / "python.exe"),
                    "args": ["-I", "-m", "localpkg"],
                },
                "other": {"command": "missing-program"},
            }
        },
    )
    reports = scan(env)
    assert tool_names(reports["npm-global"]) == ["forecast"]
    assert tool_names(reports["uv-tool"]) == ["forecast"]
    assert tool_names(reports["module"]) == ["forecast"]
    other = reports["other"].tools
    assert other is not None
    assert not other.analyzed


def test_vendored_python_libraries_are_skipped(env: HostEnvironment, write_text: WriteText) -> None:
    extension = env.app_config / "Claude" / "Claude Extensions" / "pyext"
    write_text(
        extension / "manifest.json",
        json.dumps(
            {
                "name": "pyext",
                "server": {
                    "type": "python",
                    "mcp_config": {
                        "command": "python",
                        "args": ["${__dirname}/server/main.py"],
                        "env": {"PYTHONPATH": "${__dirname}/server/lib"},
                    },
                },
            }
        ),
    )
    write_text(extension / "server" / "main.py", PY_SERVER)
    write_text(extension / "server" / "lib" / "mcp-1.0.dist-info" / "METADATA", "Name: mcp\n")
    write_text(extension / "server" / "lib" / "mcp" / "cli" / "claude.py", "import os\n")
    reports = scan(env)
    collection = reports["pyext"].tools
    assert collection is not None
    assert tool_names(reports["pyext"]) == ["forecast"]
    assert collection.files_scanned == 1


def test_duplicate_keys_matter_only_in_mcp_sections(
    env: HostEnvironment, write_text: WriteText
) -> None:
    write_text(
        env.app_config / "Code" / "User" / "settings.json",
        '{"editor.fontSize": 12, "editor.fontSize": 14,'
        ' "mcp": {"servers": {"a": {"command": "x"}, "a": {"command": "y"}}}}',
    )
    write_text(env.home / ".gemini" / "settings.json", '{"theme": "a", "theme": "b"}')
    report = analyze(env, AnalysisOptions())
    duplicates = [f for f in report.file_findings if f.rule_id == "G12-004"]
    assert [f.params["key"] for f in duplicates] == ["mcp → servers → a"]


def test_same_name_is_compared_only_where_it_loads_together(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    write_json(desktop(env), {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "a"]}}})
    write_json(
        env.home / ".cursor" / "mcp.json",
        {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "b"]}}},
    )
    write_json(
        env.home / ".claude.json",
        {
            "mcpServers": {
                "db": {"type": "stdio", "command": "uvx", "args": ["db"]},
                "same": {"type": "stdio", "command": "node", "args": ["s.js"]},
            },
            "projects": {
                str(env.cwd): {"mcpServers": {"sqlite": {"command": "uvx", "args": ["one"]}}},
                str(env.home / "other"): {
                    "mcpServers": {"sqlite": {"command": "uvx", "args": ["two"]}}
                },
            },
        },
    )
    write_json(
        env.cwd / ".mcp.json",
        {
            "mcpServers": {
                "db": {"command": "uvx", "args": ["db", "--evil"]},
                "same": {"command": "node", "args": ["s.js"]},
            }
        },
    )
    report = analyze(env, AnalysisOptions(tools=False))
    flagged = sorted(
        (entry.server.name, entry.server.source.scope.value)
        for entry in report.servers
        if any(f.rule_id == "G12-003" for f in entry.findings)
    )
    assert flagged == [("db", "project"), ("db", "user")]


def test_unreadable_configs_make_the_scan_incomplete(
    env: HostEnvironment, write_text: WriteText
) -> None:
    write_text(desktop(env), '{"mcpServers": {"a": {"command": "x"},}}')
    report = analyze(env, AnalysisOptions())
    assert not report.complete
    assert any(error.startswith("source@") for error in report.errors)
    assert [f.rule_id for f in report.file_findings] == ["G12-006"]


def test_network_projects_are_never_touched(
    env: HostEnvironment, write_json: WriteJson, monkeypatch: pytest.MonkeyPatch
) -> None:
    shares = [
        "//fileserver/share/team-project",
        "\\\\wsl.localhost\\Ubuntu\\home\\me\\app",
        "//wsl$/Ubuntu/home/me/app",
    ]
    write_json(
        env.home / ".claude.json",
        {"projects": {share: {"mcpServers": {}} for share in shares}},
    )
    touched: list[str] = []
    original = discovery_module._existing_dir

    def spy(path: Path) -> bool:
        touched.append(str(path))
        return original(path)

    monkeypatch.setattr(discovery_module, "_existing_dir", spy)
    discover(env, DiscoveryOptions())
    assert all(not remote_path(Path(item)) for item in touched)
    assert len(touched) == 1
    assert remote_path(Path("//server/share/x"))
    assert remote_path(Path("\\\\wsl$\\Ubuntu"))
    assert not remote_path(env.cwd)


def test_client_specific_syntax(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    write_json(
        env.home / ".copilot" / "mcp-config.json",
        {"mcpServers": {"local-one": {"type": "local", "command": "npx", "args": ["-y", "x"]}}},
    )
    codex = env.home / ".codex" / "config.toml"
    codex.parent.mkdir(parents=True)
    codex.write_bytes(
        b'[mcp_servers.remote]\r\nurl = "https://mcp.example.test/mcp"\r\n'
        b'http_headers = { "X-Team" = "blue" }\r\n'
        b'bearer_token_env_var = "MY_TOKEN"\r\n'
        b"\r\n[mcp_servers.legacy]\r\n"
        b'url = "https://legacy.example.test/mcp"\r\nbearer_token = "plain-value"\r\n'
    )
    servers = {s.name: s for s in discover(env, DiscoveryOptions()).servers}
    assert servers["local-one"].transport is Transport.STDIO
    remote = servers["remote"]
    assert dict(remote.headers) == {"X-Team": "blue", "Authorization": "Bearer ${MY_TOKEN}"}
    assert remote.location.line == 1
    assert servers["legacy"].headers["Authorization"] == "Bearer plain-value"
    assert servers["legacy"].location.line == 6
    report = analyze(env, AnalysisOptions(tools=False))
    local = next(entry for entry in report.servers if entry.server.name == "local-one")
    assert "G12-002" not in {f.rule_id for f in local.findings}


def test_protected_entries_point_to_the_right_lines(
    env: HostEnvironment, write_text: WriteText
) -> None:
    command, args = wrap(launcher(), "fs", "npx", ["-y", "@scope/fs-server", "C:\\"])
    lines = ["{", '  "mcpServers": {', '    "fs": {', f'      "command": {json.dumps(command)},']
    lines.append('      "args": [')
    lines.extend(f"        {json.dumps(arg)}," for arg in args[:-1])
    lines.append(f"        {json.dumps(args[-1])}")
    lines += ["      ]", "    }", "  }", "}"]
    write_text(desktop(env), "\n".join(lines) + "\n")
    server = next(s for s in discover(env, DiscoveryOptions()).servers if s.name == "fs")
    text = desktop(env).read_text(encoding="utf-8").splitlines()

    def at(pointer: str) -> str:
        line = server.locate(pointer).line
        assert line is not None
        return text[line - 1]

    assert server.shielded
    assert at("/mcpServers/fs/command").strip() == '"npx",'
    for index, arg in enumerate(server.args):
        assert json.dumps(arg) in at(f"/mcpServers/fs/args/{index}")


def test_wrappers_that_are_not_this_guardia_are_reported(
    env: HostEnvironment, write_json: WriteJson, tmp_path: Path
) -> None:
    impostor = tmp_path / "Public" / "guardia.exe"
    impostor.parent.mkdir(parents=True)
    impostor.write_bytes(b"MZ")
    entries = {}
    for name, starter in (
        ("current", launcher()),
        ("impostor", [str(impostor)]),
        ("moved", [str(tmp_path / "gone" / "guardia.exe")]),
    ):
        command, args = wrap(starter, name, "node", ["harmless.js"])
        entries[name] = {"command": command, "args": args}
    write_json(desktop(env), {"mcpServers": entries})
    reports = scan(env, tools=False)
    assert "G12-008" not in {f.rule_id for f in reports["current"].findings}
    assert "G12-009" not in {f.rule_id for f in reports["current"].findings}
    assert "G12-008" in {f.rule_id for f in reports["impostor"].findings}
    assert "G12-009" in {f.rule_id for f in reports["moved"].findings}


def test_a_crash_in_one_server_leaves_the_others_analyzed(
    env: HostEnvironment, write_json: WriteJson, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_json(
        desktop(env),
        {"mcpServers": {"bad": {"command": "node", "args": ["a.js"]}, "good": {"command": "x"}}},
    )

    def flaky(server: ServerEntry, environment: HostEnvironment) -> object:
        if server.name == "bad":
            raise RuntimeError("boom")
        return collect_tools(server, environment)

    monkeypatch.setattr(analysis_module, "collect_tools", flaky)

    def broken(*_: object, **__: object) -> object:
        raise ValueError("baseline")

    monkeypatch.setattr(analysis_module, "run_baseline", broken)
    report = analyze(env, AnalysisOptions())
    reports = {entry.server.name: entry for entry in report.servers}
    assert reports["bad"].incomplete
    assert not reports["good"].incomplete
    assert not report.complete
    assert any("RuntimeError" in error for error in report.errors)
    assert any(error.startswith("baseline:") for error in report.errors)
    assert report.baseline is not None
    assert report.baseline.status == "error"


def test_custom_config_folders_and_gemini_extensions(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    custom = replace(
        env, codex_home=env.home / "codexhome", claude_config_dir=env.home / "claudecfg"
    )
    write_text(custom.home / "codexhome" / "config.toml", '[mcp_servers.c]\ncommand = "node"\n')
    write_json(custom.home / "claudecfg" / ".claude.json", {"mcpServers": {"k": {"command": "x"}}})
    extension = env.home / ".gemini" / "extensions" / "weather"
    write_text(extension / "server.js", JS_SERVER)
    write_json(
        extension / "gemini-extension.json",
        {
            "name": "weather",
            "mcpServers": {"gw": {"command": "node", "args": ["${extensionPath}/server.js"]}},
        },
    )
    servers = {s.name: s for s in discover(custom, DiscoveryOptions()).servers}
    assert servers["c"].source.client is Client.CODEX
    assert servers["k"].source.client is Client.CLAUDE_CODE
    assert servers["gw"].source.client is Client.GEMINI_CLI
    assert servers["gw"].source.scope is Scope.PLUGIN
    reports = scan(custom)
    assert tool_names(reports["gw"]) == ["forecast"]


def test_plugin_cache_keeps_live_plugins_only(env: HostEnvironment, write_json: WriteJson) -> None:
    cache = env.home / ".claude" / "plugins" / "cache" / "market"
    old = cache / "tools" / "1.0.0"
    new = cache / "tools" / "1.1.0"
    write_json(old / ".mcp.json", {"mcpServers": {"tools-server": {"command": "x"}}})
    write_json(new / ".mcp.json", {"mcpServers": {"tools-server": {"command": "y"}}})
    write_json(new / "examples" / "demo" / ".mcp.json", {"mcpServers": {"demo": {"command": "z"}}})
    write_json(
        cache / "off" / "2.0.0" / ".mcp.json", {"mcpServers": {"off-server": {"command": "w"}}}
    )
    write_json(env.home / ".claude" / "settings.json", {"enabledPlugins": {"off@market": False}})
    old_time = new.stat().st_mtime - 1000
    os.utime(old, (old_time, old_time))
    servers = [
        s for s in discover(env, DiscoveryOptions()).servers if s.source.scope is Scope.PLUGIN
    ]
    names = sorted((s.name, s.command, s.enabled) for s in servers)
    assert names == [("off-server", "w", False), ("tools-server", "y", True)]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows drive types")
def test_local_drives_are_not_remote(env: HostEnvironment) -> None:
    assert not remote_path(Path("C:\\"))
