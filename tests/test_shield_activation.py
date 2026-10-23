from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from guardia.analysis import AnalysisOptions, analyze
from guardia.cli import main
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.activation import ActivationStore, Outcome, Support, candidates
from guardia.shield.wrapping import launcher, unwrap, wrap
from tests.conftest import WriteJson, WriteText

FAKE = Path(__file__).parent / "corpus" / "shield" / "fake_server.py"


def desktop_config(env: HostEnvironment) -> Path:
    return env.app_config / "Claude" / "claude_desktop_config.json"


def setup(env: HostEnvironment, write_json: WriteJson, write_text: WriteText) -> None:
    write_json(
        desktop_config(env),
        {
            "mcpServers": {
                "fake": {"command": sys.executable, "args": ["-I", str(FAKE)], "env": {"A": "1"}},
                "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                "remote": {"url": "https://example.test/mcp"},
            },
            "otherSetting": True,
        },
    )
    write_json(
        env.home / ".cursor" / "mcp.json",
        {"mcpServers": {"cursor-one": {"command": "node", "args": ["a.js"]}}},
    )
    write_text(
        env.app_config / "Code" / "User" / "settings.json",
        '{\n  // my comment\n  "mcp": {"servers": {"vscode-one": {"command": "node", "args": ["v.js"]}}}\n}\n',
    )
    write_text(
        env.home / ".codex" / "config.toml",
        '[mcp_servers.codex-one]\ncommand = "node"\nargs = ["c.js"]\n',
    )
    write_json(
        env.home / ".claude.json",
        {
            "projects": {
                "C:/Users/demo/app": {
                    "mcpServers": {"project-one": {"command": "node", "args": ["p.js"]}}
                }
            }
        },
    )


def supports(env: HostEnvironment) -> dict[str, Support]:
    found = candidates(discover(env, DiscoveryOptions(skills=False)))
    return {c.server.name: c.support for c in found}


def store(env: HostEnvironment) -> tuple[ActivationStore, Ledger]:
    ledger = Ledger(env.data_dir, RAW_PROTECTOR)
    return ActivationStore(env.data_dir, ledger), ledger


def servers(env: HostEnvironment, *names: str) -> list[Any]:
    inventory = discover(env, DiscoveryOptions(skills=False))
    return [s for s in inventory.servers if s.name in names]


def test_unwrap_recognizes_only_shield_wrappers() -> None:
    command, args = wrap(
        [r"C:\venv\Scripts\python.exe", "-m", "guardia"], "gh", "npx", ["-y", "pkg"]
    )
    unwrapped = unwrap(command, args)
    assert unwrapped is not None
    assert (unwrapped.command, unwrapped.args, unwrapped.name) == ("npx", ("-y", "pkg"), "gh")
    assert unwrap(r"C:\G\guardia.exe", ["shield", "--nome", "x", "--", "node", "s.js"]) is not None
    cases: list[tuple[str | None, list[str]]] = [
        ("npx", ["-y", "pkg"]),
        ("python", ["-m", "other", "scudo", "--", "x"]),
        ("python", ["-m", "guardia", "scan"]),
        ("guardia", ["scudo", "--server", "x"]),
        ("guardia", ["scudo", "--"]),
        (None, []),
    ]
    for other, other_args in cases:
        assert unwrap(other, other_args) is None


def test_launcher_uses_the_running_guardia(monkeypatch: pytest.MonkeyPatch) -> None:
    assert launcher() == [sys.executable, "-m", "guardia"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert launcher() == [str(Path(sys.executable).with_name("guardia.exe"))]


def test_launcher_from_the_desktop_app_points_to_the_command_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "GuardiaMCP" / "GuardiaMCP.exe"))
    assert launcher() == [str(tmp_path / "GuardiaMCP" / "guardia.exe")]
    command, args = wrap(launcher(), "github", "npx", ["-y", "server"])
    assert unwrap(command, args) is not None


def test_support_classification(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    found = supports(env)
    assert found["fake"] is Support.AUTO
    assert found["github"] is Support.AUTO
    assert found["remote"] is Support.REMOTE
    assert found["cursor-one"] is Support.AUTO
    assert found["vscode-one"] is Support.MANUAL_COMMENTS
    assert found["codex-one"] is Support.MANUAL_TOML
    assert found["project-one"] is Support.AUTO


def test_enable_and_disable_round_trip(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    before = desktop_config(env).read_bytes()
    activations, ledger = store(env)
    report = activations.enable(servers(env, "github", "fake"), [sys.executable, "-m", "guardia"])
    assert sorted(c.server for c in report.changes if c.outcome is Outcome.DONE) == [
        "fake",
        "github",
    ]
    assert report.backups[0].read_bytes() == before
    document = json.loads(desktop_config(env).read_text(encoding="utf-8"))
    github = document["mcpServers"]["github"]
    assert github["command"] == sys.executable
    assert github["args"] == [
        "-m",
        "guardia",
        "scudo",
        "--server",
        "github",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github",
    ]
    assert document["mcpServers"]["fake"]["env"] == {"A": "1"}
    assert document["otherSetting"] is True
    assert supports(env)["github"] is Support.PROTECTED
    rescanned = {s.name: s for s in discover(env, DiscoveryOptions(skills=False)).servers}
    assert rescanned["github"].shielded
    assert rescanned["github"].command == "npx"
    assert rescanned["github"].args == ("-y", "@modelcontextprotocol/server-github")
    again = activations.enable(servers(env, "github"), [sys.executable, "-m", "guardia"])
    assert [c.outcome for c in again.changes] == [Outcome.CHANGED]
    undone = activations.disable(["github", "fake"])
    assert sorted(c.server for c in undone.changes if c.outcome is Outcome.DONE) == [
        "fake",
        "github",
    ]
    assert json.loads(desktop_config(env).read_bytes()) == json.loads(before)
    assert activations.records() == []
    events = [r["event"] for r in ledger.records()]
    assert events == ["shield_enabled", "shield_disabled"]


def test_claude_code_project_pointers_with_slashes(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    activations, _ = store(env)
    report = activations.enable(servers(env, "project-one"), ["guardia"])
    assert [c.outcome for c in report.changes] == [Outcome.DONE]
    document = json.loads((env.home / ".claude.json").read_text(encoding="utf-8"))
    entry = document["projects"]["C:/Users/demo/app"]["mcpServers"]["project-one"]
    assert entry["args"][:4] == ["scudo", "--server", "project-one", "--"]


def test_user_edits_are_never_overwritten(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    activations, _ = store(env)
    activations.enable(servers(env, "github"), ["guardia"])
    document = json.loads(desktop_config(env).read_text(encoding="utf-8"))
    document["mcpServers"]["github"]["args"].append("--my-change")
    desktop_config(env).write_text(json.dumps(document), encoding="utf-8")
    report = activations.disable(["github"])
    assert [c.outcome for c in report.changes] == [Outcome.CHANGED]
    assert "--my-change" in desktop_config(env).read_text(encoding="utf-8")
    assert len(activations.records()) == 1
    assert [c.outcome for c in activations.disable(["nope"]).changes] == [Outcome.NOT_RECORDED]


def test_stale_plan_is_not_written(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    activations, _ = store(env)
    stale = servers(env, "github")
    document = json.loads(desktop_config(env).read_text(encoding="utf-8"))
    document["mcpServers"]["github"]["command"] = "node"
    desktop_config(env).write_text(json.dumps(document), encoding="utf-8")
    report = activations.enable(stale, ["guardia"])
    assert [c.outcome for c in report.changes] == [Outcome.CHANGED]
    assert (
        json.loads(desktop_config(env).read_text(encoding="utf-8"))["mcpServers"]["github"][
            "command"
        ]
        == "node"
    )


def test_v1_still_scans_the_original_command(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    options = AnalysisOptions(baseline=False, ledger=False, tools=False)
    before = sorted(
        f.rule_id for f in analyze(env, options).findings if f.params.get("server") == "github"
    )
    original = servers(env, "github")[0].fingerprint
    activations, _ = store(env)
    activations.enable(servers(env, "github"), [sys.executable, "-m", "guardia"])
    after = sorted(
        f.rule_id for f in analyze(env, options).findings if f.params.get("server") == "github"
    )
    assert before
    assert after == before
    assert servers(env, "github")[0].fingerprint == original


def test_the_connected_entry_really_starts_the_shield(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText, tmp_path: Path
) -> None:
    setup(env, write_json, write_text)
    activations, _ = store(env)
    activations.enable(servers(env, "fake"), [sys.executable, "-m", "guardia"])
    entry = json.loads(desktop_config(env).read_text(encoding="utf-8"))["mcpServers"]["fake"]
    process = subprocess.run(
        [entry["command"], *entry["args"]],
        input=b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
        capture_output=True,
        timeout=60,
        env={
            **os.environ,
            "LOCALAPPDATA": str(tmp_path / "local"),
            "GUARDIA_LANG": "en",
        },
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout) == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert b'Shield active for "fake"' in process.stderr


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def test_cli_setup_commands(
    env: HostEnvironment, write_json: WriteJson, write_text: WriteText
) -> None:
    setup(env, write_json, write_text)
    code, output = run_cli(env, "scudo", "elenco", "--lingua", "it")
    assert code == 0
    assert "github (Claude Desktop): non protetto, collegabile in automatico" in output
    assert "vscode-one (VS Code): non protetto: il file contiene commenti" in output
    assert "Server protetti dallo Scudo: 0 su 7." in output
    assert run_cli(env, "scudo", "attiva", "--lingua", "it")[0] == 2
    before = desktop_config(env).read_bytes()
    code, output = run_cli(env, "scudo", "attiva", "--server", "github", "--lingua", "it")
    assert code == 0
    assert "Nessuna modifica fatta" in output
    assert "--conferma" in output
    code, output = run_cli(env, "shield", "enable", "--server", "github", "--lang", "en")
    assert "--confirm " in output
    assert "--conferma" not in output
    assert desktop_config(env).read_bytes() == before
    code, output = run_cli(
        env, "scudo", "attiva", "--server", "vscode-one", "--server", "nope", "--lingua", "it"
    )
    assert "Server non trovato: «nope»." in output
    assert '"scudo",' in output
    code, output = run_cli(
        env, "shield", "enable", "--server", "github", "--confirm", "--lang", "en"
    )
    assert code == 0
    assert "Done: github" in output
    assert "Backup copy:" in output
    code, output = run_cli(env, "scudo", "elenco", "--lingua", "it")
    assert "github (Claude Desktop): PROTETTO dallo Scudo" in output
    code, output = run_cli(env, "scudo", "disattiva", "--tutti", "--lingua", "it")
    assert "Rimetterei la configurazione originale" in output
    code, output = run_cli(env, "scudo", "disattiva", "--tutti", "--conferma", "--lingua", "it")
    assert code == 0
    assert json.loads(desktop_config(env).read_bytes()) == json.loads(before)
    assert run_cli(env, "scudo", "disattiva", "--tutti", "--lingua", "it")[0] == 1
