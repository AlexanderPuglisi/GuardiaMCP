from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from guardia.cli import main
from guardia.i18n import Translator
from guardia.inventory import HostEnvironment
from guardia.ledger import KEY_FILE, Ledger
from guardia.redact import REDACTED
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.commands import example_text
from guardia.shield.engine import Context, Engine, argument_matches, redact
from guardia.shield.inspector import RulesInspector
from guardia.shield.messages import SHIELD_BLOCKED
from guardia.shield.patterns import home_text, leaves, normalize_path
from guardia.shield.policy import (
    SIGNATURE_FILE,
    ApprovalError,
    LockReason,
    PolicyState,
    PolicyWatcher,
    approve_rules,
    load_policy,
    rules_path,
)
from guardia.shield.rules import Action, Level, Phase, parse_rules
from tests.test_shield import SERVER, LiveShield, request

HOME = home_text(r"C:\Users\Demo")
SECRET = "ghp_" + "A1b2C3d4E5" * 4


def ruleset(text: str) -> Any:
    result = parse_rules(text, HOME)
    assert result.ruleset is not None, [(i.code, i.line, i.params) for i in result.issues]
    return result.ruleset


def rules(*blocks: str, default: str = "consenti") -> str:
    return f'versione = 1\npredefinito = "{default}"\n' + "\n".join(blocks)


def rule(body: str) -> str:
    return "[[regola]]\n" + body.strip() + "\n"


def evaluate(text: str, **context: Any) -> Any:
    values = {"phase": Phase.CALL, "server": "srv", "method": "tools/call"} | context
    return Engine(ruleset(text), HOME).evaluate(Context(**values))


def codes(text: str) -> list[tuple[str, str, int | None]]:
    return [(i.level.value, i.code, i.line) for i in parse_rules(text, HOME).issues]


@pytest.mark.parametrize("language", ["it", "en"])
def test_examples_are_valid_without_warnings(language: str) -> None:
    result = parse_rules(example_text(language), HOME)
    assert result.issues == []
    assert result.ruleset is not None
    assert len(result.ruleset.rules) == 5


def test_keys_and_values_are_bilingual_and_mixable() -> None:
    text = (
        'version = 1\ndefault = "block"\n'
        '[[rule]]\nnome = "mixed"\naction = "consenti"\nstrumento = "a"\nphase = ["chiamata", "list"]\n'
        '[[rule]]\nname = "other"\nazione = "redact"\ncontent.segreti = true\n'
    )
    parsed = ruleset(text)
    assert parsed.default is Action.BLOCK
    assert [r.action for r in parsed.rules] == [Action.ALLOW, Action.REDACT]
    assert parsed.rules[0].phases == {Phase.CALL, Phase.LIST}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("versione = 1\n[[regola]\n", ("error", "toml", 2)),
        ("predefinito = 'consenti'\n", ("error", "bad_version", None)),
        ("versione = 2\n", ("error", "bad_version", 1)),
        ("versione = 1\npredefinito = 'oscura'\n", ("error", "bad_default", 2)),
        ("versione = 1\nregole = []\n", ("error", "unknown_key_hint", None)),
        (rules(rule('nome = "a"\nazione = "bloca"')), ("error", "bad_action", 5)),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nstrumeto = "x"')),
            ("error", "unknown_key_hint", 6),
        ),
        (rules(rule('nome = "a"\nazione = "blocca"\ncolore = 1')), ("error", "unknown_key", 6)),
        (
            rules(rule('nome = "a"\nazione = "blocca"\naction = "block"')),
            ("error", "duplicate_key", 6),
        ),
        (rules(rule('azione = "blocca"')), ("error", "missing_name", 3)),
        (rules(rule('nome = "a"')), ("error", "missing_action", 3)),
        (rules(rule('nome = "a"\nazione = "blocca"\nfase = "chiama"')), ("error", "bad_phase", 6)),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nargomento.regex = "(unclosed"')),
            ("error", "bad_regex", 6),
        ),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nargomento.percorso = 3')),
            ("error", "not_strings", 6),
        ),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nargomento.percorso = []')),
            ("error", "not_strings", 6),
        ),
        (rules(rule('nome = "a"\nazione = "blocca"\nargomento = 3')), ("error", "not_table", 6)),
        (
            rules(rule('nome = "a"\nazione = "blocca"\ncontenuto.segreti = "si"')),
            ("error", "not_bool", 6),
        ),
        (
            rules(rule('nome = "a"\nazione = "blocca"\ncontenuto.dimensione_max = 0')),
            ("error", "bad_number", 6),
        ),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nfrequenza = { massimo = 0, secondi = 60 }')),
            ("error", "bad_number", 6),
        ),
        (
            rules(
                rule('nome = "a"\nazione = "blocca"\nfrequenza = { massimo = true, secondi = 60 }')
            ),
            ("error", "bad_number", 6),
        ),
        (rules(rule('nome = "a"\nazione = "blocca"\nattiva = "no"')), ("error", "not_bool", 6)),
        (
            rules(rule('nome = "a"\nazione = "oscura"\nfase = "elenco"\ncontenuto.segreti = true')),
            ("error", "redact_on_list", 3),
        ),
        (
            rules(rule('nome = "a"\nazione = "blocca"\nargomento.percorso = "' + "x" * 600 + '"')),
            ("error", "pattern_too_long", 6),
        ),
    ],
)
def test_errors_point_to_the_right_line(text: str, expected: tuple[str, str, int | None]) -> None:
    found = codes(text)
    assert expected in found, found
    assert parse_rules(text, HOME).ruleset is None


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (
            'nome = "a"\nazione = "blocca"\nfase = "risultato"\nargomento.percorso = "~/.ssh/**"',
            "argument_never_matches",
        ),
        ('nome = "a"\nazione = "chiedi"\nstrumento = "x"', "ask_blocks_for_now"),
        ('nome = "a"\nazione = "registra"', "matches_everything"),
        ('nome = "a"\nazione = "oscura"\nstrumento = "x"', "redacts_everything"),
    ],
)
def test_warnings_do_not_block_the_file(body: str, code: str) -> None:
    text = rules(rule(body))
    assert ("warning", code, 3) in codes(text)
    assert parse_rules(text, HOME).ruleset is not None


def test_rule_headers_use_one_language_per_file() -> None:
    text = 'version = 1\n[[rule]]\nname = "a"\naction = "log"\n[[regola]]\nnome = "b"\nazione = "registra"\n'
    assert ("error", "mixed_rule_tables", 2) in codes(text)


def test_duplicate_names_and_disabled_rules() -> None:
    text = rules(
        rule('nome = "same"\nazione = "registra"\nstrumento = "a"'),
        rule('nome = "same"\nazione = "registra"\nstrumento = "b"'),
        rule('nome = "off"\nazione = "blocca"\nattiva = false'),
    )
    result = parse_rules(text, HOME)
    assert result.ruleset is not None
    assert [r.name for r in result.ruleset.rules] == ["same", "same"]
    assert any(i.code == "duplicate_name" and i.level is Level.WARNING for i in result.issues)


@pytest.mark.parametrize(
    ("value", "blocked"),
    [
        (r"C:\Users\demo\.ssh\id_rsa", True),
        ("~/.ssh/config", True),
        ("~/progetti/../.ssh/id_rsa", True),
        ("%USERPROFILE%\\.ssh\\known_hosts", True),
        ("$HOME/.ssh/id_ed25519", True),
        ("file:///C:/Users/Demo/.ssh/id_rsa", True),
        ("C:/USERS/DEMO/.SSH/ID_RSA", True),
        (r"C:\Users\demo\.sshx\notes", False),
        (r"C:\Users\other\.ssh\id_rsa", False),
        ("readme.md", False),
    ],
)
def test_path_normalization(value: str, blocked: bool) -> None:
    text = rules(rule('nome = "ssh"\nazione = "blocca"\nargomento.percorso = "~/.ssh/**"'))
    result = evaluate(text, tool="read", arguments={"path": value})
    assert (result.action is Action.BLOCK) is blocked


def test_relative_paths_need_double_star_patterns() -> None:
    text = rules(
        rule('nome = "env"\nazione = "blocca"\nargomento.percorso = ["**/.env", "**/.ssh/**"]')
    )
    for value in [".env", "app/.env", "../../.ssh/id_rsa", "C:/proj/sub/.ENV"]:
        assert evaluate(text, arguments={"p": value}).action is Action.BLOCK, value
    assert evaluate(text, arguments={"p": "app/.env.example"}).action is Action.ALLOW


def test_hosts_and_allowlists() -> None:
    allowlist = rules(
        rule(
            'nome = "only github"\nazione = "blocca"\nargomento.host_non_in = ["github.com", "*.github.com"]'
        )
    )
    assert evaluate(allowlist, arguments={"u": "https://api.github.com/x"}).action is Action.ALLOW
    assert evaluate(allowlist, arguments={"u": "see https://evil.example/x"}).action is Action.BLOCK
    assert (
        evaluate(allowlist, arguments={"u": "https://user:pw@EVIL.example./x"}).action
        is Action.BLOCK
    )
    assert evaluate(allowlist, arguments={"u": "no url here"}).action is Action.ALLOW
    deny = rules(rule('nome = "ngrok"\nazione = "blocca"\nargomento.host = "*.ngrok-free.app"'))
    assert evaluate(deny, arguments={"u": "https://a.ngrok-free.app/c"}).action is Action.BLOCK
    assert (
        evaluate(deny, arguments={"u": "https://ngrok-free.app.evil.com/c"}).action is Action.ALLOW
    )


def test_fields_limit_where_conditions_look() -> None:
    text = rules(
        rule(
            'nome = "url only"\nazione = "blocca"\nargomento.campo = "url"\nargomento.contiene = "secret"'
        )
    )
    assert evaluate(text, arguments={"url": "x?secret=1"}).action is Action.BLOCK
    assert evaluate(text, arguments={"body": "secret"}).action is Action.ALLOW
    assert evaluate(text, arguments={"nested": {"url": "SECRET"}}).action is Action.BLOCK


def test_names_match_without_case() -> None:
    text = rules(
        rule(
            'nome = "deletes"\nazione = "blocca"\nserver = "git*"\nstrumento = "delete_*"\nmetodo = "tools/*"'
        )
    )
    assert evaluate(text, server="GitHub", tool="Delete_Repo").action is Action.BLOCK
    assert evaluate(text, server="gitlab", tool="list_repos").action is Action.ALLOW
    assert evaluate(text, server="other", tool="delete_repo").action is Action.ALLOW


def test_strictest_action_wins_regardless_of_order() -> None:
    text = rules(
        rule('nome = "allow"\nazione = "consenti"\nstrumento = "x"'),
        rule('nome = "block"\nazione = "blocca"\nstrumento = "x"'),
        rule('nome = "log"\nazione = "registra"\nstrumento = "x"'),
        rule('nome = "redact"\nazione = "oscura"\nstrumento = "y"\ncontenuto.segreti = true'),
        rule('nome = "log y"\nazione = "registra"\nstrumento = "y"'),
    )
    result = evaluate(text, tool="x")
    assert result.action is Action.BLOCK
    assert result.names == ["allow", "block", "log"]
    assert evaluate(text, tool="y", content={"a": SECRET}).action is Action.REDACT
    assert evaluate(text, tool="z").defaulted


def test_default_applies_to_calls_and_lists_but_not_results() -> None:
    text = rules(rule('nome = "echo"\nazione = "consenti"\nstrumento = "echo"'), default="blocca")
    assert evaluate(text, tool="echo").action is Action.ALLOW
    assert evaluate(text, tool="other").action is Action.BLOCK
    assert (
        evaluate(text, phase=Phase.LIST, method="tools/list", tool="other").action is Action.BLOCK
    )
    assert evaluate(text, phase=Phase.RESULT, tool="other").action is Action.ALLOW
    assert (
        evaluate(text, phase=Phase.SERVER_REQUEST, method="sampling/createMessage").action
        is Action.BLOCK
    )


def test_content_conditions() -> None:
    text = rules(
        rule('nome = "secrets"\nazione = "blocca"\nfase = "risultato"\ncontenuto.segreti = true'),
        rule('nome = "big"\nazione = "registra"\ncontenuto.dimensione_max = 100'),
        rule(
            'nome = "words"\nazione = "blocca"\nfase = "elenco"\ncontenuto.regex = "(?i)ignore\\\\s+previous"'
        ),
    )
    assert evaluate(text, phase=Phase.RESULT, content={"t": f"key {SECRET}"}).action is Action.BLOCK
    assert evaluate(text, phase=Phase.RESULT, content={"t": "nothing"}).action is Action.ALLOW
    assert evaluate(text, size=101).names == ["big"]
    assert evaluate(text, size=100).defaulted
    listed = evaluate(
        text, phase=Phase.LIST, tool="t", content={"description": "Please IGNORE   previous"}
    )
    assert listed.action is Action.BLOCK


def test_rate_limit_counts_per_server() -> None:
    now = [0.0]
    engine = Engine(
        ruleset(
            rules(
                rule(
                    'nome = "rate"\nazione = "blocca"\nmetodo = "tools/call"\nfrequenza = { massimo = 2, secondi = 10 }'
                )
            )
        ),
        HOME,
        clock=lambda: now[0],
    )
    context = Context(Phase.CALL, "a", "tools/call")
    assert [engine.evaluate(context).action for _ in range(3)] == [
        Action.ALLOW,
        Action.ALLOW,
        Action.BLOCK,
    ]
    assert engine.evaluate(Context(Phase.CALL, "b", "tools/call")).action is Action.ALLOW
    assert engine.evaluate(context, record=False).action is Action.BLOCK
    now[0] = 11.0
    assert engine.evaluate(context).action is Action.ALLOW


def test_redaction_rewrites_only_what_matches() -> None:
    parsed = ruleset(
        rules(
            rule('nome = "secrets"\nazione = "oscura"\ncontenuto.segreti = true'),
            rule('nome = "words"\nazione = "oscura"\ncontenuto.contiene = "Mario Rossi"'),
            rule('nome = "paths"\nazione = "oscura"\nargomento.percorso = "~/private/**"'),
        )
    )
    value = {
        "a": f"token {SECRET}",
        "b": "Name: MARIO ROSSI",
        "c": "~/private/x.txt",
        "d": 3,
        "e": "safe",
    }
    redacted = redact(value, parsed.rules, HOME)
    assert redacted == {
        "a": f"token {REDACTED}",
        "b": f"Name: {REDACTED}",
        "c": REDACTED,
        "d": 3,
        "e": "safe",
    }
    wipe = ruleset(rules(rule('nome = "all"\nazione = "oscura"\nstrumento = "x"')))
    assert redact({"x": ["a", "b"]}, wipe.rules, HOME) == {"x": [REDACTED, REDACTED]}


def test_leaves_and_normalization_limits() -> None:
    assert normalize_path("a\nb", HOME) is None
    assert normalize_path("", HOME) is None
    deep: Any = "x"
    for _ in range(200):
        deep = {"k": deep}
    assert leaves(deep) == []
    condition = parse_rules(
        rules(rule('nome = "p"\nazione = "blocca"\nargomento.percorso = "**/x"')), HOME
    )
    assert condition.ruleset is not None
    argument = condition.ruleset.rules[0].argument
    assert argument is not None
    assert not argument_matches(argument, {}, HOME)


def write_rules(directory: Path, text: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    rules_path(directory).write_text(text, encoding="utf-8")


def test_policy_lifecycle(tmp_path: Path) -> None:
    directory = tmp_path / "data"
    assert load_policy(directory, HOME, RAW_PROTECTOR).state is PolicyState.NONE
    write_rules(directory, example_text("it"))
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.UNAPPROVED
    result, _ = approve_rules(directory, HOME, RAW_PROTECTOR)
    assert result.ruleset is not None
    active = load_policy(directory, HOME, RAW_PROTECTOR)
    assert active.state is PolicyState.ACTIVE
    assert active.ruleset is not None
    assert len(active.ruleset.rules) == 5
    events = [r["event"] for r in Ledger(directory, RAW_PROTECTOR).records()]
    assert events == ["rules_approved"]
    write_rules(directory, example_text("it") + "\n")
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.MODIFIED
    approve_rules(directory, HOME, RAW_PROTECTOR)
    signature = json.loads((directory / SIGNATURE_FILE).read_text(encoding="utf-8"))
    signature["mac"] = "0" * 64
    (directory / SIGNATURE_FILE).write_text(json.dumps(signature), encoding="utf-8")
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.MODIFIED
    approve_rules(directory, HOME, RAW_PROTECTOR)
    rules_path(directory).unlink()
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.MISSING
    write_rules(directory, example_text("it"))
    approve_rules(directory, HOME, RAW_PROTECTOR)
    (directory / KEY_FILE).unlink()
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.KEY


def test_invalid_rules_are_never_signed(tmp_path: Path) -> None:
    directory = tmp_path / "data"
    write_rules(directory, "versione = 1\n[[regola]]\nnome = 'x'\n")
    result, _ = approve_rules(directory, HOME, RAW_PROTECTOR)
    assert result.ruleset is None
    assert not (directory / SIGNATURE_FILE).exists()
    assert load_policy(directory, HOME, RAW_PROTECTOR).reason is LockReason.UNAPPROVED


def test_approval_fails_closed_when_the_ledger_cannot_be_written(tmp_path: Path) -> None:
    directory = tmp_path / "data"
    write_rules(directory, example_text("it"))
    (directory / "registro.lock").mkdir()
    with pytest.raises(ApprovalError):
        approve_rules(directory, HOME, RAW_PROTECTOR)
    assert not (directory / SIGNATURE_FILE).exists()


def test_watcher_reloads_after_approval(tmp_path: Path) -> None:
    directory = tmp_path / "data"
    watcher = PolicyWatcher(directory, HOME, RAW_PROTECTOR, interval=0)
    assert watcher.current().state is PolicyState.NONE
    write_rules(directory, example_text("en"))
    assert watcher.current().reason is LockReason.UNAPPROVED
    approve_rules(directory, HOME, RAW_PROTECTOR)
    assert watcher.current().state is PolicyState.ACTIVE


class BrokenLedger(Ledger):
    def append(self, event: str, data: Any) -> dict[str, Any]:
        raise OSError("disk full")


def shield_with_rules(
    tmp_path: Path,
    text: str | None,
    *flags: str,
    approve: bool = True,
    ledger: Ledger | None = None,
) -> tuple[LiveShield, Ledger, list[str]]:
    directory = tmp_path / "data"
    directory.mkdir(parents=True, exist_ok=True)
    if text is not None:
        write_rules(directory, text)
        if approve:
            approve_rules(directory, HOME, RAW_PROTECTOR)
    used = ledger or Ledger(directory, RAW_PROTECTOR)
    reports: list[str] = []
    inspector = RulesInspector(
        server="fake",
        policy=PolicyWatcher(directory, HOME, RAW_PROTECTOR, interval=0).current,
        home=HOME,
        ledger=used,
        t=Translator("it"),
        report=reports.append,
    )
    return LiveShield(*flags, inspector=inspector), used, reports


def call(request_id: int, tool: str, arguments: dict[str, Any]) -> bytes:
    return request(request_id, "tools/call", {"name": tool, "arguments": arguments})


def test_live_block_by_path_never_reaches_the_server(tmp_path: Path) -> None:
    shield, ledger, reports = shield_with_rules(tmp_path, example_text("it"))
    answer = shield.ask(call(1, "echo", {"text": "~/Progetti/../.ssh/id_rsa"}))
    assert answer["error"]["code"] == SHIELD_BLOCKED
    assert "«Mai toccare chiavi SSH, credenziali e file .env»" in answer["error"]["message"]
    assert shield.ask(call(2, "echo", {"text": "hello"}))["result"]["content"][0]["text"] == "hello"
    shield.close()
    decisions = [r["data"] for r in ledger.records() if r["event"] == "shield_decision"]
    assert [d["action"] for d in decisions] == ["block", "allow"]
    assert decisions[0]["tool"] == "echo"
    assert "id_rsa" not in json.dumps(decisions)
    assert any("blocca" in line for line in reports)


def test_live_list_hides_tools(tmp_path: Path) -> None:
    text = rules(rule('nome = "hide echo"\nazione = "blocca"\nfase = "elenco"\nstrumento = "echo"'))
    shield, ledger, _ = shield_with_rules(tmp_path, text)
    answer = shield.ask(request(1, "tools/list"))
    assert answer["result"]["tools"] == []
    shield.close()
    hidden = [r["data"] for r in ledger.records() if r["event"] == "shield_decision"]
    assert hidden[0]["hidden"] == ["echo"]


def test_live_redaction_of_results_and_arguments(tmp_path: Path) -> None:
    text = rules(
        rule('nome = "results"\nazione = "oscura"\nfase = "risultato"\ncontenuto.segreti = true'),
        rule('nome = "names"\nazione = "oscura"\nfase = "chiamata"\nargomento.contiene = "Mario"'),
    )
    shield, _, _ = shield_with_rules(tmp_path, text)
    result = shield.ask(call(1, "echo", {"text": f"here {SECRET} end"}))
    assert result["result"]["content"][0]["text"] == f"here {REDACTED} end"
    echoed = shield.ask(call(2, "echo", {"text": "hi Mario"}))
    assert echoed["result"]["content"][0]["text"] == f"hi {REDACTED}"
    shield.close()


def test_live_allowlist_mode(tmp_path: Path) -> None:
    text = rules(
        rule('nome = "echo ok"\nazione = "consenti"\nstrumento = "echo"'),
        rule(
            'nome = "handshake"\nazione = "consenti"\nmetodo = ["initialize", "tools/list", "ping"]'
        ),
        default="blocca",
    )
    shield, _, _ = shield_with_rules(tmp_path, text)
    assert "result" in shield.ask(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    assert [t["name"] for t in shield.ask(request(2, "tools/list"))["result"]["tools"]] == ["echo"]
    assert shield.ask(call(3, "echo", {"text": "x"}))["result"]["content"][0]["text"] == "x"
    blocked = shield.ask(call(4, "delete_all", {}))
    assert "comportamento predefinito" in blocked["error"]["message"]
    shield.close()


def test_live_ask_blocks_until_the_window_exists(tmp_path: Path) -> None:
    text = rules(rule('nome = "confirm"\nazione = "chiedi"\nstrumento = "echo"'))
    shield, _, _ = shield_with_rules(tmp_path, text)
    answer = shield.ask(call(1, "echo", {"text": "x"}))
    assert "finestra di conferma non è ancora disponibile" in answer["error"]["message"]
    shield.close()


def test_live_lockdown_when_rules_are_not_approved(tmp_path: Path) -> None:
    shield, _, _ = shield_with_rules(tmp_path, example_text("it"), approve=False)
    answer = shield.ask(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    assert answer["error"]["code"] == SHIELD_BLOCKED
    assert "non approvate" in answer["error"]["message"]
    assert shield.ask(request(2, "ping"))["error"]["code"] == SHIELD_BLOCKED
    shield.close()


def test_live_rules_reload_during_a_session(tmp_path: Path) -> None:
    shield, _, _ = shield_with_rules(tmp_path, None)
    assert "result" in shield.ask(call(1, "echo", {"text": "~/.ssh/id_rsa"}))
    directory = tmp_path / "data"
    write_rules(directory, example_text("it"))
    approve_rules(directory, HOME, RAW_PROTECTOR)
    assert shield.ask(call(2, "echo", {"text": "~/.ssh/id_rsa"}))["error"]["code"] == SHIELD_BLOCKED
    shield.close()


def test_live_server_requests_are_checked(tmp_path: Path) -> None:
    text = rules(
        rule(
            'nome = "no sampling"\nazione = "blocca"\nfase = "richiesta_server"\nmetodo = "sampling/*"'
        ),
        rule(
            'nome = "no passwords"\nazione = "blocca"\nfase = "richiesta_server"\ncontenuto.contiene = "password"'
        ),
    )
    shield, _, _ = shield_with_rules(tmp_path, text, "--server-request")
    shield.send(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    received = [shield.receive(), shield.receive()]
    assert any("result" in m for m in received)
    assert {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {"received": "s1"},
    } in received
    shield.close()
    second, _, _ = shield_with_rules(tmp_path / "b", text, "--input-required")
    answer = second.ask(call(1, "transfer", {}))
    assert answer["error"]["code"] == SHIELD_BLOCKED
    assert "«no passwords»" in answer["error"]["message"]
    second.close()


def test_live_ledger_failure_blocks_the_call(tmp_path: Path) -> None:
    shield, _, reports = shield_with_rules(
        tmp_path, None, ledger=BrokenLedger(tmp_path / "broken", RAW_PROTECTOR)
    )
    answer = shield.ask(call(1, "echo", {"text": "x"}))
    assert answer["error"]["code"] == SHIELD_BLOCKED
    assert "non è scrivibile" in answer["error"]["message"]
    assert shield.ask(request(2, "ping"))["result"] == {}
    shield.close()
    assert any("disk full" in line for line in reports)


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def test_cli_rules_workflow(env: HostEnvironment) -> None:
    code, output = run_cli(env, "scudo", "regole", "stato", "--lingua", "it")
    assert (code, "Nessuna regola approvata" in output) == (0, True)
    assert run_cli(env, "scudo", "regole", "esempio", "--salva", "--lingua", "it")[0] == 0
    assert run_cli(env, "scudo", "regole", "esempio", "--salva", "--lingua", "it")[0] == 3
    code, output = run_cli(env, "scudo", "regole", "stato", "--lingua", "it")
    assert code == 1
    assert "BLOCCO TOTALE" in output
    code, output = run_cli(env, "scudo", "regole", "verifica", "--lingua", "it")
    assert (code, "5 regole attive" in output) == (0, True)
    code, output = run_cli(env, "scudo", "regole", "approva", "--lingua", "it")
    assert code == 0
    assert "Prima approvazione" in output
    code, output = run_cli(
        env,
        "scudo",
        "regole",
        "prova",
        "--strumento",
        "read",
        "--argomenti",
        '{"path": "~/.ssh/id_rsa"}',
        "--lingua",
        "it",
    )
    assert code == 0
    assert "Decisione: BLOCCA" in output
    code, output = run_cli(
        env, "shield", "rules", "test", "--phase", "result", "--text", f"x {SECRET}", "--lang", "en"
    )
    assert "Decision: REDACT" in output
    assert SECRET not in output
    code, output = run_cli(env, "scudo", "regole", "prova", "--argomenti", "[1]", "--lingua", "it")
    assert code == 2
    path = rules_path(env.data_dir)
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n[[regola]]\nnome = 'x'\nazione = 'blocca'\nstrumento = 'z'\n",
        encoding="utf-8",
    )
    code, output = run_cli(env, "scudo", "regole", "approva", "--lingua", "it")
    assert code == 0
    assert "+nome = 'x'" in output


def test_cli_verify_reports_errors(env: HostEnvironment, tmp_path: Path) -> None:
    broken = tmp_path / "broken.toml"
    broken.write_text("versione = 1\n[[regola]]\nnome = 'x'\nazione = 'bloca'\n", encoding="utf-8")
    code, output = run_cli(
        env, "scudo", "regole", "verifica", "--file", str(broken), "--lingua", "it"
    )
    assert code == 1
    assert "ERRORE riga 4 (regola «x»)" in output
    assert run_cli(env, "scudo", "regole", "verifica", "--lingua", "it")[0] == 2


def test_rule_test_does_not_consume_the_rate(env: HostEnvironment, tmp_path: Path) -> None:
    file = tmp_path / "rate.toml"
    file.write_text(
        rules(rule('nome = "r"\nazione = "blocca"\nfrequenza = { massimo = 1, secondi = 60 }')),
        encoding="utf-8",
    )
    for _ in range(3):
        _, output = run_cli(env, "scudo", "regole", "prova", "--file", str(file), "--lingua", "it")
        assert "CONSENTI" in output


def test_secret_never_reaches_the_ledger(tmp_path: Path) -> None:
    text = rules(rule('nome = "log all"\nazione = "registra"\nstrumento = "echo"'))
    shield, ledger, _ = shield_with_rules(tmp_path, text)
    shield.ask(call(1, "echo", {"text": SECRET}))
    shield.close()
    assert SECRET not in (tmp_path / "data" / "registro.jsonl").read_text(encoding="utf-8")
    assert ledger.verify().intact


def test_ledger_fast_path_survives_a_stale_head(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "data", RAW_PROTECTOR)
    for index in range(3):
        ledger.append("x", {"i": index})
    head = (tmp_path / "data" / "registro.head").read_bytes()
    ledger.append("x", {"i": 3})
    (tmp_path / "data" / "registro.head").write_bytes(head)
    ledger.append("x", {"i": 4})
    verification = ledger.verify()
    assert verification.records == 5
    assert [i.problem.value for i in verification.issues] == []


def test_cli_shield_applies_approved_rules_end_to_end(tmp_path: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONIOENCODING", "PYTHONUTF8"}
    }
    environment.update(GUARDIA_LANG="it", LOCALAPPDATA=str(tmp_path))
    guardia = [sys.executable, "-m", "guardia"]
    saved = subprocess.run(
        [*guardia, "scudo", "regole", "esempio", "--salva"],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert saved.returncode == 0, saved.stdout
    approved = subprocess.run(
        [*guardia, "scudo", "regole", "approva"], env=environment, capture_output=True, check=False
    )
    assert approved.returncode == 0, approved.stdout
    messages = [
        request(1, "initialize", {"protocolVersion": "2025-11-25"}),
        call(2, "echo", {"text": "type ~/.ssh/id_rsa"}),
        call(3, "echo", {"text": "hello"}),
    ]
    shielded = subprocess.run(
        [*guardia, "scudo", "--server", "demo", "--", *SERVER],
        input=b"\n".join(messages) + b"\n",
        env=environment,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert shielded.returncode == 0, shielded.stderr
    output = {m["id"]: m for m in map(json.loads, shielded.stdout.splitlines())}
    assert output[2]["error"]["code"] == SHIELD_BLOCKED
    assert output[3]["result"]["content"][0]["text"] == "hello"
    errors = shielded.stderr.decode("utf-8")
    assert "Regole attive: 5" in errors
    assert "«demo»: blocca tools/call echo" in errors
