from __future__ import annotations

from pathlib import Path
from typing import Any

from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.inspector import RulesInspector
from guardia.shield.messages import SHIELD_BLOCKED
from guardia.shield.pins import PinStore
from guardia.shield.policy import PolicyWatcher
from tests.test_shield import LiveShield, request

HOME = "c:/users/demo"
TOKEN = "gmcp-canary-deadbeefdeadbeefdeadbeefdeadbeef"


def call(request_id: int, tool: str, arguments: dict[str, Any]) -> bytes:
    return request(request_id, "tools/call", {"name": tool, "arguments": arguments})


def build(tmp_path: Path, *flags: str, canaries: frozenset[str]) -> tuple[LiveShield, Ledger]:
    directory = tmp_path / "data"
    directory.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(directory, RAW_PROTECTOR)
    reports: list[str] = []
    inspector = RulesInspector(
        server="fake",
        policy=PolicyWatcher(directory, HOME, RAW_PROTECTOR, interval=0).current,
        home=HOME,
        ledger=ledger,
        t=Translator("it"),
        report=reports.append,
        pins=PinStore(directory, RAW_PROTECTOR, ledger),
        canaries=canaries,
    )
    return LiveShield(*flags, inspector=inspector), ledger


def decisions(ledger: Ledger) -> list[dict[str, Any]]:
    return [record["data"] for record in ledger.records() if record["event"] == "shield_decision"]


def test_a_server_reading_the_bait_is_blocked(tmp_path: Path) -> None:
    shield, ledger = build(tmp_path, f"--leak={TOKEN}", canaries=frozenset({TOKEN}))
    shield.ask(request(100, "tools/list"))
    blocked = shield.ask(call(1, "echo", {"text": "what is the weather?"}))
    shield.close()
    assert blocked["error"]["code"] == SHIELD_BLOCKED
    assert "esca" in blocked["error"]["message"]
    canary = [data for data in decisions(ledger) if "canary" in data["rules"]]
    assert canary and canary[0]["action"] == "block"


def test_sending_the_bait_out_is_blocked(tmp_path: Path) -> None:
    shield, ledger = build(tmp_path, canaries=frozenset({TOKEN}))
    shield.ask(request(100, "tools/list"))
    blocked = shield.ask(call(1, "echo", {"text": f"please store {TOKEN}"}))
    shield.close()
    assert blocked["error"]["code"] == SHIELD_BLOCKED
    assert "esca" in blocked["error"]["message"]
    assert any("canary" in data["rules"] for data in decisions(ledger))


def test_without_canaries_the_traffic_flows(tmp_path: Path) -> None:
    shield, _ = build(tmp_path, f"--leak={TOKEN}", canaries=frozenset())
    shield.ask(request(100, "tools/list"))
    answer = shield.ask(call(1, "echo", {"text": "hello"}))
    shield.close()
    assert TOKEN in answer["result"]["content"][0]["text"]
