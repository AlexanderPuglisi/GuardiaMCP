from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from guardia.app.api import GuardiaApi, GuardiaUiError
from guardia.app.settings import SettingsStore
from guardia.app.shield_view import shield_state
from guardia.cli import main
from guardia.i18n import Translator
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.activation import ActivationStore, Outcome, Support, candidates
from guardia.shield.wrapping import LauncherState, launcher, launcher_state, unwrap, wrap
from tests.conftest import WriteJson

GITHUB: dict[str, Any] = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "env": {"A": "1"},
}


def config_path(env: HostEnvironment) -> Path:
    return env.app_config / "Claude" / "claude_desktop_config.json"


def entry(env: HostEnvironment) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(config_path(env).read_text(encoding="utf-8"))
    servers: dict[str, Any] = document["mcpServers"]
    return dict(servers["github"])


def protected_by(starter: list[str]) -> dict[str, Any]:
    command, args = wrap(starter, "github", GITHUB["command"], GITHUB["args"])
    return {**GITHUB, "command": command, "args": args}


def found(env: HostEnvironment) -> list[Any]:
    return candidates(discover(env, DiscoveryOptions(skills=False)))


def github(env: HostEnvironment) -> Any:
    return next(c for c in found(env) if c.server.name == "github")


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def make_api(env: HostEnvironment) -> GuardiaApi:
    return GuardiaApi(env, SettingsStore(env.data_dir), protector=RAW_PROTECTOR)


@pytest.fixture
def stale(env: HostEnvironment, write_json: WriteJson, tmp_path: Path) -> HostEnvironment:
    gone = str(tmp_path / "old-folder" / "guardia.exe")
    write_json(
        config_path(env),
        {"mcpServers": {"github": protected_by([gone])}, "keep": True},
    )
    return env


def test_launcher_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert launcher_state(tuple(launcher())) is LauncherState.CURRENT
    assert launcher_state(
        (str(Path(sys.executable).parent).upper() + "\\python.exe", "-m", "guardia")
    ) in (
        LauncherState.CURRENT,
        LauncherState.OTHER,
    )
    other = tmp_path / "other" / "guardia.exe"
    other.parent.mkdir()
    other.write_bytes(b"")
    assert launcher_state((str(other),)) is LauncherState.OTHER
    assert launcher_state((str(tmp_path / "gone" / "guardia.exe"),)) is LauncherState.MISSING
    assert launcher_state(()) is LauncherState.MISSING
    monkeypatch.setenv("PATH", str(other.parent))
    assert launcher_state(("guardia",)) is LauncherState.OTHER
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    assert launcher_state(("guardia",)) is LauncherState.MISSING


def test_unwrap_remembers_which_guardia_wraps_the_server() -> None:
    wrapped = unwrap("C:/Tools/Guardia/guardia.exe", ["scudo", "--server", "x", "--", "npx", "a"])
    assert wrapped is not None
    assert wrapped.launcher == ("C:/Tools/Guardia/guardia.exe",)
    wrapped = unwrap(sys.executable, ["-m", "guardia", "shield", "--", "node", "s.js"])
    assert wrapped is not None
    assert wrapped.launcher == (sys.executable, "-m", "guardia")


def test_missing_guardia_is_shown_and_relinked_from_the_app(stale: HostEnvironment) -> None:
    rows = shield_state(stale, Translator("it"), RAW_PROTECTOR)["servers"]
    row = next(s for s in rows if s["name"] == "github")
    assert row["launcher"] == "missing"
    assert row["can_relink"] is True
    assert row["can_disable"] is True
    assert "Guardia che non c'è più" in row["status"]
    api = make_api(stale)
    with pytest.raises(GuardiaUiError):
        api.shield_relink(row["key"], False)
    with pytest.raises(GuardiaUiError):
        api.shield_relink("nope", True)
    state = api.shield_relink(row["key"], True)
    assert state["ok"] is True, state["message"]
    assert entry(stale) == protected_by(launcher())
    assert json.loads(config_path(stale).read_text(encoding="utf-8"))["keep"] is True
    row = next(s for s in state["servers"] if s["name"] == "github")
    assert (row["launcher"], row["can_relink"]) == ("current", False)
    events = [r["event"] for r in Ledger(stale.data_dir, RAW_PROTECTOR).records()]
    assert "shield_relinked" in events
    backups = list((stale.data_dir / "backup").iterdir())
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8"))["mcpServers"]["github"][
        "command"
    ].endswith("guardia.exe")
    state = api.shield_disable(row["key"], True)
    assert state["ok"] is True, state["message"]
    assert entry(stale) == GITHUB


def test_protection_without_notes_can_still_be_removed(stale: HostEnvironment) -> None:
    assert ActivationStore(stale.data_dir).records() == []
    key = github(stale).server.key
    state = make_api(stale).shield_disable(key, True)
    assert state["ok"] is True, state["message"]
    assert entry(stale) == GITHUB
    assert github(stale).support is Support.AUTO


def test_relink_keeps_the_original_noted_at_enable_time(
    env: HostEnvironment, write_json: WriteJson, tmp_path: Path
) -> None:
    write_json(config_path(env), {"mcpServers": {"github": GITHUB}})
    store = ActivationStore(env.data_dir)
    old = [str(tmp_path / "old" / "guardia.exe")]
    assert [c.outcome for c in store.enable([github(env).server], old).changes] == [Outcome.DONE]
    report = store.relink([github(env).server], launcher())
    assert [c.outcome for c in report.changes] == [Outcome.DONE]
    records = store.records()
    assert len(records) == 1
    assert records[0]["original"] == GITHUB
    assert records[0]["wrapped"] == protected_by(launcher())
    assert [c.outcome for c in store.disable(["github"]).changes] == [Outcome.DONE]
    assert entry(env) == GITHUB


def test_relink_keeps_changes_made_meanwhile(stale: HostEnvironment) -> None:
    server = github(stale).server
    document = json.loads(config_path(stale).read_text(encoding="utf-8"))
    document["mcpServers"]["github"]["env"]["B"] = "2"
    config_path(stale).write_text(json.dumps(document), encoding="utf-8")
    report = ActivationStore(stale.data_dir).relink([server], launcher())
    assert [c.outcome for c in report.changes] == [Outcome.DONE]
    assert entry(stale)["env"] == {"A": "1", "B": "2"}
    assert unwrap(entry(stale)["command"], entry(stale)["args"]) is not None
    assert launcher_state(github(stale).server.shield_launcher) is LauncherState.CURRENT


class BrokenLedger:
    def append(self, event: str, data: dict[str, Any]) -> None:
        raise OSError("disk full")


def test_notes_are_saved_even_if_the_ledger_fails(stale: HostEnvironment) -> None:
    store = ActivationStore(stale.data_dir, cast(Ledger, BrokenLedger()))
    report = store.relink([github(stale).server], launcher())
    assert [c.outcome for c in report.changes] == [Outcome.DONE]
    assert entry(stale) == protected_by(launcher())
    records = ActivationStore(stale.data_dir).records()
    assert [r["wrapped"] for r in records] == [protected_by(launcher())]
    assert [r["original"] for r in records] == [GITHUB]


def test_relink_ignores_entries_that_are_not_protected(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    write_json(config_path(env), {"mcpServers": {"github": GITHUB}})
    report = ActivationStore(env.data_dir).relink([github(env).server], launcher())
    assert [c.outcome for c in report.changes] == [Outcome.CHANGED]
    assert entry(env) == GITHUB


def test_cli_relink_and_disable_all(stale: HostEnvironment) -> None:
    code, output = run_cli(stale, "scudo", "elenco", "--lingua", "it")
    assert code == 0
    assert "github (Claude Desktop): PROTETTO, ma da una Guardia che non c'è più" in output
    code, output = run_cli(stale, "scudo", "ricollega", "--tutti", "--lingua", "it")
    assert code == 0
    assert "Ricollegherei a questa Guardia:" in output
    assert unwrap(entry(stale)["command"], entry(stale)["args"]) is not None
    assert launcher_state(github(stale).server.shield_launcher) is LauncherState.MISSING
    code, output = run_cli(stale, "shield", "relink", "--all", "--confirm", "--lang", "en")
    assert code == 0
    assert "Done: github" in output
    assert entry(stale) == protected_by(launcher())
    code, output = run_cli(stale, "scudo", "ricollega", "--tutti", "--lingua", "it")
    assert code == 0
    assert "niente da ricollegare" in output
    code, output = run_cli(stale, "scudo", "disattiva", "--tutti", "--conferma", "--lingua", "it")
    assert code == 0
    assert entry(stale) == GITHUB


def test_cli_disable_all_also_restores_protection_without_notes(stale: HostEnvironment) -> None:
    code, output = run_cli(stale, "shield", "disable", "--all", "--lang", "en")
    assert code == 0
    assert "github" in output
    assert unwrap(entry(stale)["command"], entry(stale)["args"]) is not None
    code, _ = run_cli(stale, "shield", "disable", "--all", "--confirm", "--lang", "en")
    assert code == 0
    assert entry(stale) == GITHUB
