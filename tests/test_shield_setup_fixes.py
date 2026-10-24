from __future__ import annotations

import io
import stat
import sys
import tomllib
from pathlib import Path

import pytest

from guardia.cli import default_name, main
from guardia.i18n import Translator
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.safeio import parse_json
from guardia.shield.activation import (
    ActivationStore,
    manual_snippet,
    shield_names,
)
from guardia.shield.commands import example_text
from guardia.shield.policy import rules_path
from guardia.shield.wrapping import unwrap
from tests.conftest import WriteJson, WriteText
from tests.test_shield_activation import desktop_config, setup


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def help_text(*argv: str) -> str:
    out = io.StringIO()
    previous = sys.stdout
    sys.stdout = out
    try:
        with pytest.raises(SystemExit):
            main(list(argv))
    finally:
        sys.stdout = previous
    return out.getvalue()


def shield_name(path: Path, name: str, section: str = "mcpServers") -> str:
    entry = parse_json(path.read_text(encoding="utf-8")).value[section][name]
    wrapped = unwrap(entry["command"], entry["args"])
    assert wrapped is not None
    return wrapped.name


def test_read_only_config_does_not_lose_the_other_protections(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    cursor = env.home / ".cursor" / "mcp.json"
    cursor.chmod(stat.S_IREAD)
    try:
        code, output = run_cli(env, "shield", "enable", "--all", "--confirm", "--lang", "en")
        before = cursor.read_bytes()
    finally:
        cursor.chmod(stat.S_IREAD | stat.S_IWRITE)
    assert code == 1
    assert "Traceback" not in output
    assert 'cannot write the file of "cursor-one"' in output
    assert "Done: github" in output
    assert b"scudo" not in before
    recorded = {r["server"] for r in ActivationStore(env.data_dir).records()}
    assert {"fake", "github", "project-one"} <= recorded
    assert "cursor-one" not in recorded
    code, output = run_cli(env, "shield", "disable", "--all", "--confirm", "--lang", "en")
    assert code == 0
    assert "scudo" not in desktop_config(env).read_text(encoding="utf-8")


def test_same_name_in_two_apps_gets_separate_shield_names(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    write_json(
        desktop_config(env),
        {"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "a"]}}},
    )
    write_json(
        env.home / ".cursor" / "mcp.json",
        {
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["-y", "b"]},
                "solo": {"command": "node", "args": ["s.js"]},
            }
        },
    )
    write_json(
        env.home / ".claude.json",
        {
            "mcpServers": {"twin": {"command": "node", "args": ["u.js"]}},
            "projects": {"C:/w": {"mcpServers": {"twin": {"command": "node", "args": ["p.js"]}}}},
        },
    )
    everyone = list(discover(env, DiscoveryOptions(skills=False)).servers)
    names = shield_names(everyone, everyone)
    assert names[next(s.key for s in everyone if s.name == "solo")] == "solo"
    labels = sorted(names[s.key] for s in everyone if s.name == "filesystem")
    assert labels == ["filesystem (claude-desktop)", "filesystem (cursor)"]
    twins = [names[s.key] for s in everyone if s.name == "twin"]
    assert len(set(twins)) == 2
    assert all(label.startswith("twin (claude-code, ") for label in twins)
    code, _ = run_cli(env, "shield", "enable", "--all", "--confirm", "--lang", "en")
    assert code == 0
    assert shield_name(desktop_config(env), "filesystem") == "filesystem (claude-desktop)"
    assert shield_name(env.home / ".cursor" / "mcp.json", "filesystem") == "filesystem (cursor)"
    assert shield_name(env.home / ".cursor" / "mcp.json", "solo") == "solo"


def test_manual_snippet_for_codex_is_toml(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    codex = next(
        s for s in discover(env, DiscoveryOptions(skills=False)).servers if s.name == "codex-one"
    )
    parsed = tomllib.loads(manual_snippet(codex, ["C:\\G\\guardia.exe"], "codex-one (codex)"))
    assert parsed["command"] == "C:\\G\\guardia.exe"
    assert parsed["args"] == ["scudo", "--server", "codex-one (codex)", "--", "node", "c.js"]
    code, output = run_cli(env, "shield", "enable", "--server", "codex-one", "--lang", "en")
    assert code == 1
    line = next(line for line in output.splitlines() if line.startswith("args = ["))
    assert line.endswith('"scudo", "--server", "codex-one", "--", "node", "c.js"]')
    assert tomllib.loads(line)["args"][-2:] == ["node", "c.js"]


def test_unreadable_configs_are_listed(env: HostEnvironment, write_text: WriteText) -> None:
    write_text(desktop_config(env), '{"mcpServers": {"fetch": {"command": "uvx", "args": ["x"]},}}')
    code, output = run_cli(env, "shield", "list", "--lang", "en")
    assert code == 0
    assert "Unreadable file, its servers are not listed" in output
    assert "claude_desktop_config.json" in output
    code, output = run_cli(env, "shield", "enable", "--server", "fetch", "--lang", "en")
    assert code == 1
    assert 'Server not found: "fetch".' in output
    assert "Unreadable file" in output


def test_enable_all_when_everything_is_protected_is_fine(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    write_json(desktop_config(env), {"mcpServers": {"github": {"command": "npx", "args": ["-y"]}}})
    assert run_cli(env, "shield", "enable", "--all", "--confirm", "--lang", "en")[0] == 0
    code, output = run_cli(env, "shield", "enable", "--all", "--confirm", "--lang", "en")
    assert code == 0
    assert "already protected" in output


def test_ledger_last_must_be_a_positive_number(env: HostEnvironment) -> None:
    for value in ("0", "-5", "x"):
        with pytest.raises(SystemExit) as exc:
            main(["ledger", "show", "--last", value, "--lang", "en"], env=env, stdout=io.StringIO())
        assert exc.value.code == 2


def test_tools_commands_take_the_server_name_from_either_place(env: HostEnvironment) -> None:
    need = Translator("it")("shield_rules.tools_need_server")
    for argv in (
        ("scudo", "--nome", "x", "strumenti", "approva", "--lingua", "it"),
        ("scudo", "strumenti", "approva", "--nome", "x", "--lingua", "it"),
    ):
        code, output = run_cli(env, *argv)
        assert need not in output
        assert "«x»" in output
        assert code == 1


def test_default_shield_names() -> None:
    assert (
        default_name(["npx", "-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "C:\\"])
        == "server-filesystem"
    )
    assert default_name(["C:\\nodejs\\npx.cmd", "-y", "@scope/pkg"]) == "pkg"
    assert default_name(["uvx", "mcp-server-fetch==2025.4.7"]) == "mcp-server-fetch"
    assert default_name(["pnpm", "dlx", "some-server@1.0.0"]) == "some-server"
    assert default_name(["C:\\Tools\\server.exe", "--port", "1"]) == "server"


def test_help_speaks_the_language_of_the_reader() -> None:
    english = help_text("shield", "enable", "--help", "--lang", "en")
    usage = english.split("\n\n")[0]
    assert "[--server NAME]" in usage
    assert "[--all]" in usage
    assert "[--confirm]" in usage
    assert "--tutti" not in usage
    italian = help_text("scudo", "attiva", "--help", "--lingua", "it")
    usage = italian.split("\n\n")[0]
    assert "[--nome NOME]" in usage
    assert "[--tutti]" in usage
    assert "[--conferma]" in usage
    for internal in ("SETUP_SERVERS", "TOOLS_SERVER", "TOOL_NAMES", "TEST_SERVER"):
        assert internal not in help_text("shield", "tools", "--help", "--lang", "en")
        assert internal not in help_text("shield", "rules", "--help", "--lang", "en")


def test_unexpected_errors_end_with_exit_code_3(
    env: HostEnvironment, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise RuntimeError("kaboom")

    monkeypatch.setattr("guardia.cli.analyze", boom)
    code, _ = run_cli(env, "scan", "--lang", "en")
    assert code == 3
    assert "Unexpected error (RuntimeError)" in capsys.readouterr().err


def test_missing_rules_file_given_by_hand(env: HostEnvironment, tmp_path: Path) -> None:
    code, output = run_cli(
        env, "shield", "rules", "verify", "--file", str(tmp_path / "nope.toml"), "--lang", "en"
    )
    assert code == 2
    assert "File not found" in output
    assert "example --save" not in output


def test_rules_diff_labels_follow_the_language(env: HostEnvironment) -> None:
    path = rules_path(env.data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(example_text("en"), encoding="utf-8")
    assert run_cli(env, "shield", "rules", "approve", "--lang", "en")[0] == 0
    path.write_text(example_text("en") + "\n# reviewed\n", encoding="utf-8")
    code, output = run_cli(env, "shield", "rules", "approve", "--lang", "en")
    assert code == 0
    assert "--- approved" in output
    assert "+++ new" in output
    assert "approvate" not in output
