from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from guardia.i18n import SUPPORTED_LANGUAGES, load_messages
from guardia.inventory.parsers import ParseOutcome, normalize_entry
from guardia.model import Client, ConfigSource, Scope, ServerEntry, Severity
from guardia.scanner import RULES, ScanContext
from guardia.scanner.checks import SERVER_CHECKS

CORPUS = Path(__file__).parent / "corpus" / "config_cases.toml"
CASES: list[dict[str, Any]] = tomllib.loads(CORPUS.read_text(encoding="utf-8"))["case"]
CONTEXT = ScanContext(home=Path(r"C:\Users\me"))


def build_server(case: dict[str, Any]) -> ServerEntry:
    name = case.get("name", case["id"])
    source = ConfigSource(Client.CLAUDE_DESKTOP, Scope.USER, Path("corpus.json"))
    return normalize_entry(
        name, case["server"], source, f"/mcpServers/{case['id']}", ParseOutcome()
    )


def rule_ids(server: ServerEntry) -> set[str]:
    return {finding.rule_id for check in SERVER_CHECKS for finding in check(server, CONTEXT)}


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_corpus_case_triggers_exactly_the_expected_rules(case: dict[str, Any]) -> None:
    assert rule_ids(build_server(case)) == set(case["expected"])


def test_corpus_is_balanced_and_well_formed() -> None:
    kinds = [case["kind"] for case in CASES]
    assert set(kinds) == {"benign", "malicious"}
    assert kinds.count("benign") >= 20
    assert kinds.count("malicious") >= 40
    assert len({case["id"] for case in CASES}) == len(CASES)
    for case in CASES:
        assert (case["kind"] == "benign") == (not case["expected"]), case["id"]


def test_detection_and_false_alarm_rates() -> None:
    malicious = [c for c in CASES if c["kind"] == "malicious"]
    benign = [c for c in CASES if c["kind"] == "benign"]
    detected = sum(1 for c in malicious if set(c["expected"]) <= rule_ids(build_server(c)))
    false_alarms = sum(1 for c in benign if rule_ids(build_server(c)))
    assert detected / len(malicious) == 1.0
    assert false_alarms / len(benign) == 0.0


@pytest.mark.parametrize("language", SUPPORTED_LANGUAGES)
def test_every_rule_has_complete_texts(language: str) -> None:
    messages = load_messages(language)
    for rule_id in RULES:
        for part in ("title", "why", "fix"):
            assert messages.get(f"rules.{rule_id}.{part}"), f"{language}: {rule_id}.{part}"
    for category in {rule.category for rule in RULES.values()}:
        assert messages.get(f"category.{category}"), f"{language}: {category}"
    for severity in Severity:
        assert messages.get(f"severity.{severity.label}")


def test_rule_ids_follow_the_naming_scheme() -> None:
    for rule_id, rule in RULES.items():
        assert rule.id == rule_id
        assert len(rule_id) == 7
        assert rule_id[0] == "G"
        assert rule_id[3] == "-"
