from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from guardia.cli import main, peek_language
from guardia.inventory import HostEnvironment
from tests.conftest import WriteJson

SECRET = "ghp_" + "Z9y8" * 9


@pytest.fixture
def configured(env: HostEnvironment, write_json: WriteJson) -> HostEnvironment:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github", "--token", SECRET],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": SECRET},
                },
                "evil\x1b[2Jname": {"command": "x"},
                "off": {"command": "y", "disabled": True},
            }
        },
    )
    return env


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def test_inventory_in_italian(configured: HostEnvironment) -> None:
    code, output = run_cli(configured, "--lingua", "it", "inventario")
    assert code == 0
    assert "Inventario dei server MCP" in output
    assert "Claude Desktop · utente" in output
    assert "github" in output
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in output
    assert "(disattivato)" in output
    assert "Totale: 3 server (2 attivi) in 1 file letti." in output
    assert "non ha avviato nessun server" in output


def test_inventory_in_english(configured: HostEnvironment) -> None:
    code, output = run_cli(configured, "--lang=en", "inventory")
    assert code == 0
    assert "MCP server inventory" in output
    assert "Total: 3 servers (2 enabled) in 1 files read." in output


def test_secrets_never_appear_in_any_output(configured: HostEnvironment, tmp_path: Path) -> None:
    _, text = run_cli(configured, "--lang", "en", "inventory")
    _, as_json = run_cli(configured, "--lang", "en", "inventory", "--json")
    target = tmp_path / "out.json"
    run_cli(configured, "--lang", "en", "inventory", "--json", "--output", str(target))
    for output in (text, as_json, target.read_text(encoding="utf-8")):
        assert SECRET not in output


def test_terminal_control_characters_are_neutralized(configured: HostEnvironment) -> None:
    _, text = run_cli(configured, "--lang", "en", "inventory")
    _, as_json = run_cli(configured, "--lang", "en", "inventory", "--json")
    assert "\x1b" not in text
    assert "\x1b" not in as_json
    assert "evil\\u001b[2Jname" in text


def test_json_output_is_valid_and_complete(configured: HostEnvironment) -> None:
    _, output = run_cli(configured, "--lang", "en", "inventory", "--json")
    data = json.loads(output)
    assert data["tool"] == "guardia-mcp"
    names = {server["name"] for server in data["servers"]}
    assert names == {"github", "evil\x1b[2Jname", "off"}
    github = next(s for s in data["servers"] if s["name"] == "github")
    assert github["env_keys"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert github["args"][-1] == "[REDACTED]"


def test_output_file_is_written(configured: HostEnvironment, tmp_path: Path) -> None:
    target = tmp_path / "inventory.txt"
    code, output = run_cli(configured, "--lang", "it", "inventario", "--salva", str(target))
    assert code == 0
    assert "Risultato salvato in" in output
    assert "github" in target.read_text(encoding="utf-8")


def test_empty_inventory_message(env: HostEnvironment) -> None:
    _, output = run_cli(env, "--lang", "it", "inventario")
    assert "Nessun server MCP trovato." in output


def test_all_sources_lists_missing_files(env: HostEnvironment) -> None:
    _, output = run_cli(env, "--lang", "it", "inventario", "--tutte-le-fonti")
    assert "non presente" in output


def test_no_command_prints_help(env: HostEnvironment) -> None:
    code, output = run_cli(env, "--lang", "en")
    assert code == 0
    assert "inventory" in output


@pytest.mark.parametrize(
    "argv",
    [
        ("--lang", "en", "inventory"),
        ("inventory", "--lang", "en"),
        ("inventario", "--lingua=en"),
    ],
)
def test_language_option_works_before_and_after_the_command(
    configured: HostEnvironment, argv: tuple[str, ...]
) -> None:
    code, output = run_cli(configured, *argv)
    assert code == 0
    assert "MCP server inventory" in output


def test_peek_language() -> None:
    assert peek_language(["--lang", "it", "inventory"]) == "it"
    assert peek_language(["--lingua=en"]) == "en"
    assert peek_language(["inventory"]) is None
