from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from guardia.app.api import GuardiaApi, GuardiaUiError
from guardia.app.settings import SettingsStore
from guardia.inventory import HostEnvironment
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.commands import example_text
from guardia.shield.pins import PinStore
from guardia.shield.policy import rules_path
from tests.conftest import WriteJson


def make_api(env: HostEnvironment) -> GuardiaApi:
    return GuardiaApi(env, SettingsStore(env.data_dir), protector=RAW_PROTECTOR)


@pytest.fixture
def configured(env: HostEnvironment, write_json: WriteJson) -> HostEnvironment:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {
            "mcpServers": {
                "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}
            }
        },
    )
    return env


def config(env: HostEnvironment) -> dict[str, object]:
    path = env.app_config / "Claude" / "claude_desktop_config.json"
    document: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    return document


def test_shield_state_lists_servers_rules_and_pending(configured: HostEnvironment) -> None:
    PinStore(configured.data_dir, RAW_PROTECTOR).review("github", {"a": "1"})
    PinStore(configured.data_dir, RAW_PROTECTOR).review("github", {"a": "2"})
    state = make_api(configured).shield()
    assert state["rules"]["state"] == "none"
    assert state["protected"] == 0
    github = next(s for s in state["servers"] if s["name"] == "github")
    assert github["can_enable"] is True
    assert github["status"] == "non protetto, collegabile in automatico"
    assert state["pending"]["items"][0]["tool"] == "a"
    assert state["pending"]["items"][0]["reason"] == "cambiato"


def test_protect_and_unprotect_from_the_app(configured: HostEnvironment) -> None:
    api = make_api(configured)
    key = next(s["key"] for s in api.shield()["servers"] if s["name"] == "github")
    for confirmed in (False, 1, "true", None):
        with pytest.raises(GuardiaUiError):
            api.shield_enable(key, confirmed)
    with pytest.raises(GuardiaUiError):
        api.shield_enable("not-a-key", True)
    state = api.shield_enable(key, True)
    assert state["ok"] is True
    assert "Fatto: github" in state["message"]
    assert state["protected"] == 1
    servers = config(configured)["mcpServers"]
    assert isinstance(servers, dict)
    assert servers["github"]["command"] == sys.executable
    assert state["events"][0]["label"] == "Server collegato allo Scudo"
    with pytest.raises(GuardiaUiError):
        api.shield_disable("other", True)
    state = api.shield_disable("github", True)
    assert state["ok"] is True
    servers = config(configured)["mcpServers"]
    assert isinstance(servers, dict)
    assert servers["github"]["command"] == "npx"


def test_approve_tools_and_rules_from_the_app(configured: HostEnvironment) -> None:
    pins = PinStore(configured.data_dir, RAW_PROTECTOR, Ledger(configured.data_dir, RAW_PROTECTOR))
    pins.review("github", {"a": "1"})
    pins.review("github", {"a": "2", "b": "3"})
    api = make_api(configured)
    with pytest.raises(GuardiaUiError):
        api.shield_approve_tools("github", False)
    state = api.shield_approve_tools("github", True)
    assert state["ok"] is True
    assert state["pending"]["items"] == []
    assert api.shield_approve_tools("github", True)["ok"] is False
    assert api.shield_approve_rules(True)["ok"] is False
    rules_path(configured.data_dir).write_text(example_text("it"), encoding="utf-8")
    assert api.shield()["rules"]["state"] == "locked"
    state = api.shield_approve_rules(True)
    assert state["ok"] is True
    assert state["rules"]["state"] == "active"
    rules_path(configured.data_dir).write_text(
        "versione = 1\n[[regola]]\nnome = 'x'\n", encoding="utf-8"
    )
    assert api.shield_approve_rules(True)["ok"] is False


def test_manual_servers_offer_a_snippet(env: HostEnvironment) -> None:
    path = env.app_config / "Code" / "User" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        '{\n  // c\n  "mcp": {"servers": {"v": {"command": "node", "args": ["v.js"]}}}\n}\n',
        encoding="utf-8",
    )
    server = next(s for s in make_api(env).shield()["servers"] if s["name"] == "v")
    assert server["can_enable"] is False
    assert '"scudo"' in server["snippet"]
    assert Path(path).read_text(encoding="utf-8").count("// c") == 1
