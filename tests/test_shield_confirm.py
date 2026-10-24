from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from guardia.app.confirm import ConfirmApi, confirm_strings
from guardia.app.page import build_page
from guardia.i18n import Translator, load_messages
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.confirm import (
    Answer,
    ConfirmRequest,
    RequestError,
    WindowConfirmer,
    answer_json,
    parse_answer,
    parse_request,
)
from guardia.shield.inspector import RulesInspector
from guardia.shield.messages import SHIELD_BLOCKED
from guardia.shield.policy import PolicyWatcher, approve_rules, rules_path
from guardia.shield.proxy import MAX_DEFERRED
from tests.test_shield import LiveShield, request

HOME = "c:/users/demo"
SECRET = "ghp_" + "A1b2C3d4E5" * 4
ASK_ECHO = 'versione = 1\n[[regola]]\nnome = "confirm"\nazione = "chiedi"\nstrumento = "echo"\n'
WEB = Path(__file__).parent.parent / "src" / "guardia" / "app" / "web"


class FakeConfirmer:
    def __init__(self, *answers: Answer, hold: threading.Event | None = None) -> None:
        self.answers = list(answers)
        self.requests: list[ConfirmRequest] = []
        self.hold = hold

    def __call__(self, confirm: ConfirmRequest) -> Answer:
        self.requests.append(confirm)
        if self.hold is not None:
            self.hold.wait(20)
        return self.answers.pop(0) if self.answers else Answer.BLOCK


def call(request_id: int, tool: str, arguments: dict[str, Any]) -> bytes:
    return request(request_id, "tools/call", {"name": tool, "arguments": arguments})


def shield(
    tmp_path: Path, confirmer: FakeConfirmer, rules: str = ASK_ECHO
) -> tuple[LiveShield, Ledger, list[str]]:
    directory = tmp_path / "data"
    directory.mkdir(parents=True, exist_ok=True)
    rules_path(directory).write_text(rules, encoding="utf-8")
    approve_rules(directory, HOME, RAW_PROTECTOR)
    ledger = Ledger(directory, RAW_PROTECTOR)
    reports: list[str] = []
    inspector = RulesInspector(
        server="fake",
        policy=PolicyWatcher(directory, HOME, RAW_PROTECTOR, interval=0).current,
        home=HOME,
        ledger=ledger,
        t=Translator("it"),
        report=reports.append,
        confirm=confirmer,
    )
    return LiveShield(inspector=inspector), ledger, reports


def answers(ledger: Ledger) -> list[str]:
    return [
        r["data"].get("answer")
        for r in ledger.records()
        if r["event"] == "shield_decision" and "answer" in r["data"]
    ]


def test_allowed_confirmation_forwards_the_call(tmp_path: Path) -> None:
    confirmer = FakeConfirmer(Answer.ALLOW)
    live, ledger, reports = shield(tmp_path, confirmer)
    result = live.ask(call(1, "echo", {"text": "ciao"}))
    assert result["result"]["content"][0]["text"] == "ciao"
    live.close()
    asked = confirmer.requests[0]
    assert (asked.server, asked.tool, asked.method, asked.language) == (
        "fake",
        "echo",
        "tools/call",
        "it",
    )
    assert asked.reasons == ("Regola «confirm»",)
    assert asked.details == "text: ciao"
    assert answers(ledger) == ["allow"]
    assert any("conferma per echo: consentito" in line for line in reports)


@pytest.mark.parametrize(
    ("answer", "text"),
    [
        (Answer.BLOCK, "Hai rifiutato questa azione"),
        (Answer.TIMEOUT, "Nessuna risposta nella finestra di conferma"),
        (Answer.UNAVAILABLE, "Non è stato possibile mostrare la finestra"),
    ],
)
def test_refused_confirmation_blocks_with_the_reason(
    tmp_path: Path, answer: Answer, text: str
) -> None:
    live, ledger, _ = shield(tmp_path, FakeConfirmer(answer))
    blocked = live.ask(call(1, "echo", {"text": "x"}))
    assert blocked["error"]["code"] == SHIELD_BLOCKED
    assert "Regola: «confirm»" in blocked["error"]["message"]
    assert text in blocked["error"]["message"]
    live.close()
    assert answers(ledger) == [answer.value]


def test_remembered_choice_skips_the_window_for_ten_minutes(tmp_path: Path) -> None:
    confirmer = FakeConfirmer(Answer.ALLOW_REMEMBER)
    live, ledger, _ = shield(tmp_path, confirmer)
    assert "result" in live.ask(call(1, "echo", {"text": "a"}))
    assert "result" in live.ask(call(2, "echo", {"text": "b"}))
    live.close()
    assert len(confirmer.requests) == 1
    assert answers(ledger) == ["allow_remember", "remembered"]


def test_secrets_are_redacted_in_the_window_but_reach_the_server_when_allowed(
    tmp_path: Path,
) -> None:
    confirmer = FakeConfirmer(Answer.ALLOW)
    live, _, _ = shield(tmp_path, confirmer, rules="versione = 1\n")
    live.ask(request(1, "tools/list"))
    result = live.ask(call(2, "echo", {"text": f"use {SECRET}"}))
    assert result["result"]["content"][0]["text"] == "use [REDACTED]"
    live.close()
    shown = confirmer.requests[0]
    assert SECRET not in shown.details
    assert "[REDACTED]" in shown.details
    assert any("contengono un segreto" in reason for reason in shown.reasons)


def test_waiting_for_confirmation_does_not_stop_other_messages(tmp_path: Path) -> None:
    hold = threading.Event()
    live, _, _ = shield(tmp_path, FakeConfirmer(Answer.ALLOW, hold=hold))
    live.send(call(1, "echo", {"text": "slow"}))
    assert live.ask(request(2, "ping"))["id"] == 2
    hold.set()
    assert live.receive()["result"]["content"][0]["text"] == "slow"
    live.close()


def test_too_many_waiting_confirmations_are_blocked(tmp_path: Path) -> None:
    hold = threading.Event()
    confirmer = FakeConfirmer(*([Answer.ALLOW] * MAX_DEFERRED), hold=hold)
    live, _, _ = shield(tmp_path, confirmer)
    for index in range(MAX_DEFERRED + 1):
        live.send(call(index, "echo", {"text": str(index)}))
    first = live.receive()
    assert first["id"] == MAX_DEFERRED
    assert first["error"]["code"] == SHIELD_BLOCKED
    hold.set()
    released = {live.receive()["id"] for _ in range(MAX_DEFERRED)}
    assert released == set(range(MAX_DEFERRED))
    live.close()
    assert any("Too many requests waiting for confirmation" in line for line in live.reports)


def valid_request(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "server": "github",
        "method": "tools/call",
        "tool": "delete_repo",
        "reasons": ["Regola «x»"],
        "details": "{}",
        "language": "it",
        "seconds": 60,
    }
    document.update(changes)
    return document


def test_confirmation_request_round_trip() -> None:
    original = ConfirmRequest("srv", "tools/call", "t\u202e", ("a",), "d", "en", 30)
    parsed = parse_request(original.to_json())
    assert parsed.tool == "t\\u202e"
    assert (parsed.server, parsed.reasons, parsed.seconds, parsed.language) == (
        "srv",
        ("a",),
        30,
        "en",
    )


@pytest.mark.parametrize(
    "document",
    [
        valid_request(seconds=1),
        valid_request(seconds=True),
        valid_request(seconds=10_000),
        valid_request(language="fr"),
        valid_request(reasons="x"),
        valid_request(reasons=["x"] * 20),
        valid_request(server=3),
        ["not", "an", "object"],
    ],
)
def test_invalid_confirmation_requests(document: Any) -> None:
    with pytest.raises(RequestError):
        parse_request(json.dumps(document).encode())


def test_answers_are_parsed_strictly() -> None:
    assert parse_answer(answer_json(Answer.ALLOW)) is Answer.ALLOW
    assert parse_answer(b'{"answer": "allow_remember"}') is Answer.ALLOW_REMEMBER
    for data in (
        None,
        b"",
        b"yes",
        b'{"answer": "maybe"}',
        b'{"answer": "unavailable"}',
        b"[1]",
        b"\xff",
    ):
        assert parse_answer(data) is Answer.UNAVAILABLE


def script(tmp_path: Path, body: str, name: str = "confirm_fake.py") -> list[str]:
    path = tmp_path / name
    path.write_text("import sys, json, time\nsys.stdin.buffer.read()\n" + body, encoding="utf-8")
    return [sys.executable, "-I", str(path)]


def test_window_confirmer_talks_to_a_separate_process(tmp_path: Path) -> None:
    confirm = ConfirmRequest("srv", "tools/call", "t", (), "", "it", 5)
    allow = WindowConfirmer(
        script(tmp_path, 'sys.stdout.write(json.dumps({"answer": "allow"}))'), margin=10
    )
    assert allow(confirm) is Answer.ALLOW
    failing = WindowConfirmer(script(tmp_path, "sys.exit(1)", "failing.py"), margin=10)
    assert failing(confirm) is Answer.UNAVAILABLE
    garbage = WindowConfirmer(script(tmp_path, 'sys.stdout.write("ok")', "garbage.py"), margin=10)
    assert garbage(confirm) is Answer.UNAVAILABLE
    missing = WindowConfirmer(["guardia-confirm-program-that-does-not-exist"], margin=1)
    assert missing(confirm) is Answer.UNAVAILABLE


def test_a_window_that_never_answers_is_killed(tmp_path: Path) -> None:
    confirm = ConfirmRequest("srv", "tools/call", "t", (), "", "it", 5)
    stuck = WindowConfirmer(script(tmp_path, "time.sleep(60)"), margin=0)
    started = time.monotonic()
    assert stuck(confirm) is Answer.UNAVAILABLE
    assert time.monotonic() - started < 20


def test_confirm_command_rejects_bad_input() -> None:
    process = subprocess.run(
        [sys.executable, "-m", "guardia", "scudo", "conferma"],
        input=b"not json",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert process.returncode == 2
    assert process.stdout == b""


def test_window_api_accepts_only_known_answers() -> None:
    api = ConfirmApi(
        ConfirmRequest("srv", "tools/call", "t", ("r",), "d", "en", 30), Translator("en")
    )
    details = api.details()
    assert details["ui"]["allow"] == "Allow"
    assert details["reasons"] == ["r"]
    api.answer("unavailable")
    assert api._result is Answer.BLOCK
    api.answer("allow")
    assert api._result is Answer.BLOCK
    other = ConfirmApi(ConfirmRequest("srv", "m", "", (), "", "it", 30), Translator("it"))
    other.answer({"evil": True})
    assert other._result is Answer.BLOCK
    public = {name for name in dir(api) if not name.startswith("_")}
    assert public == {"answer", "details"}


def test_window_texts_exist_in_both_languages() -> None:
    italian = confirm_strings(Translator("it"))
    english = confirm_strings(Translator("en"))
    assert set(italian) == set(english)
    assert {"title", "allow", "block", "remember", "countdown", "lead_tool"} <= set(italian)
    assert {k for k in load_messages("it") if k.startswith("confirm.")} == {
        k for k in load_messages("en") if k.startswith("confirm.")
    }


def test_window_page_is_strict() -> None:
    page = build_page("confirm.html", "confirm.css", "confirm.js")
    assert "default-src 'none'" in page
    assert "connect-src 'none'" in page
    assert page.count("<script") == 1
    script_text = (WEB / "confirm.js").read_text(encoding="utf-8")
    for forbidden in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "fetch(",
        "new Function",
    ):
        assert forbidden not in script_text
    assert re.search(r'id="block"', page)
    assert "pywebview-drag-region" in page


class OneWindowAtATime(FakeConfirmer):
    def __init__(self, *answers: Answer) -> None:
        super().__init__(*answers)
        self.lock = threading.Lock()

    def __call__(self, confirm: ConfirmRequest) -> Answer:
        with self.lock:
            time.sleep(0.3)
            return super().__call__(confirm)


def test_remembered_choice_covers_calls_already_waiting(tmp_path: Path) -> None:
    confirmer = OneWindowAtATime(Answer.ALLOW_REMEMBER)
    live, ledger, _ = shield(tmp_path, confirmer)
    live.send(call(1, "echo", {"text": "a"}))
    live.send(call(2, "echo", {"text": "b"}))
    results = {live.receive()["id"], live.receive()["id"]}
    live.close()
    assert results == {1, 2}
    assert len(confirmer.requests) == 1
    assert sorted(answers(ledger)) == ["allow_remember", "remembered"]
