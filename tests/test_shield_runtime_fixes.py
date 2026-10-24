from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.confirm import (
    CONFIRM_SECONDS,
    MAX_DETAILS,
    Answer,
    ConfirmRequest,
    WindowConfirmer,
    parse_answer,
    parse_request,
)
from guardia.shield.engine import Context, Engine
from guardia.shield.inspector import RulesInspector
from guardia.shield.messages import SHIELD_BLOCKED
from guardia.shield.patterns import normalize_path
from guardia.shield.policy import PolicyWatcher, approve_rules
from guardia.shield.process import (
    ServerProcess,
    UnsafeArgumentError,
    cmd_quote,
    command_line,
)
from guardia.shield.protections import credential_request, elicitations, input_elicitations
from guardia.shield.rules import Action, Level, Phase, parse_rules
from guardia.shield.runner import exit_status
from guardia.shield.windows import remote_drive
from tests.test_shield import SERVER, LiveShield, notification, request
from tests.test_shield_confirm import FakeConfirmer, answers
from tests.test_shield_rules import HOME, call, rule, rules, ruleset, shield_with_rules, write_rules

WINDOWS = sys.platform == "win32"
GUARDIA_SHIELD = (sys.executable, "-m", "guardia", "scudo", "--senza-registro", "--")
TIMEOUT = 30
STUBBORN = (
    "import json, os, sys, time\n"
    "with open(sys.argv[1], 'w') as handle:\n"
    "    handle.write(str(os.getpid()))\n"
    "for line in sys.stdin.buffer:\n"
    "    message = json.loads(line)\n"
    "    if 'id' in message:\n"
    "        answer = {'jsonrpc': '2.0', 'id': message['id'], 'result': {}}\n"
    "        sys.stdout.buffer.write(json.dumps(answer).encode() + b'\\n')\n"
    "        sys.stdout.buffer.flush()\n"
    "time.sleep(60)\n"
)
DUMP_ARGS = (
    "import json, sys\n"
    "with open(sys.argv[1], 'w', encoding='utf-8') as handle:\n"
    "    json.dump(sys.argv[2:], handle)\n"
)
INTERRUPT = (
    "import signal, sys, threading, time\n"
    "from pathlib import Path\n"
    "from guardia.cli import main\n"
    "pid_file = Path(sys.argv[1])\n"
    "def later():\n"
    "    while not pid_file.exists() or not pid_file.read_text().strip():\n"
    "        time.sleep(0.05)\n"
    "    time.sleep(0.5)\n"
    "    signal.raise_signal(signal.SIGINT)\n"
    "threading.Thread(target=later, daemon=True).start()\n"
    "sys.exit(main(['scudo', '--senza-registro', '--', *sys.argv[2:]]))\n"
)
TRICKY = [
    "postgresql://u@h/db?sslmode=disable&connect_timeout=10",
    "x|y",
    'json={"a": 1, "b": "c d"}',
    "a b",
    "",
    "^caret^",
    "trail\\",
    "<in> >out",
    "(paren)",
    "50% off",
    'end"',
    'a\\"b',
    "comma,semi;eq=",
]


def alive(pid: int) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(0x00100000 | 0x1000, False, pid)
    if not handle:
        return False
    try:
        return bool(kernel32.WaitForSingleObject(ctypes.c_void_p(handle), 0) == 0x102)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def wait_for(path: Path, seconds: float = TIMEOUT) -> str:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists() and path.read_text(encoding="utf-8").strip():
            return path.read_text(encoding="utf-8").strip()
        time.sleep(0.05)
    raise AssertionError(f"{path} never appeared")


def gone(pid: int, seconds: float = 10) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.1)
    return False


def environment(tmp_path: Path) -> dict[str, str]:
    values = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONIOENCODING", "PYTHONUTF8"}
    }
    values.update(GUARDIA_LANG="it", LOCALAPPDATA=str(tmp_path))
    return values


def launcher(tmp_path: Path, script: str, name: str, *extra: str) -> Path:
    body = tmp_path / f"{name}.py"
    body.write_text(script, encoding="utf-8")
    words = " ".join(f'"{part}"' for part in extra)
    command = tmp_path / f"{name}.cmd"
    command.write_text(f'@"{sys.executable}" -I "{body}" {words} %*\r\n', encoding="ascii")
    return command


def test_exit_codes_above_the_signed_range_keep_their_value() -> None:
    assert exit_status(0xC000013A) == 0xC000013A - (1 << 32)
    assert exit_status(7) == 7
    assert exit_status(0) == 0
    assert exit_status(-1) == -1


def test_server_exit_while_the_client_stays_connected(tmp_path: Path) -> None:
    process = subprocess.Popen(
        [*GUARDIA_SHIELD, *SERVER],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment(tmp_path),
    )
    assert process.stdin is not None
    assert process.stderr is not None
    process.stdin.write(request(1, "exit") + b"\n")
    process.stdin.flush()
    code = process.wait(TIMEOUT)
    errors = process.stderr.read().decode("utf-8", "replace")
    process.stdin.close()
    assert code == 7, errors
    assert "Fatal Python error" not in errors
    assert "Scudo fermato" in errors


@pytest.mark.skipif(not WINDOWS, reason="Windows exit codes")
def test_crash_exit_codes_of_the_server_are_preserved(tmp_path: Path) -> None:
    crash = f"import os; os._exit({0xC000013A - (1 << 32)})"
    done = subprocess.run(
        [*GUARDIA_SHIELD, sys.executable, "-I", "-c", crash],
        input=b"",
        capture_output=True,
        timeout=60,
        env=environment(tmp_path),
        check=False,
    )
    assert done.returncode == 0xC000013A, done.stderr


def test_rate_limits_count_only_calls() -> None:
    now = [0.0]
    engine = Engine(
        ruleset(
            rules(
                rule(
                    'nome = "brake"\nazione = "blocca"\nstrumento = "send_email"\n'
                    "frequenza = { massimo = 2, secondi = 3600 }"
                )
            )
        ),
        HOME,
        clock=lambda: now[0],
    )
    listed = Context(Phase.LIST, "mail", "tools/list", "send_email", content={})
    called = Context(Phase.CALL, "mail", "tools/call", "send_email")
    result = Context(Phase.RESULT, "mail", "tools/call", "send_email", content={"ok": 1})
    for _ in range(5):
        assert engine.evaluate(listed).action is Action.ALLOW
    assert engine.evaluate(called).action is Action.ALLOW
    assert engine.evaluate(result).action is Action.ALLOW
    assert engine.evaluate(called).action is Action.ALLOW
    assert engine.evaluate(result).action is Action.ALLOW
    assert engine.evaluate(called).action is Action.BLOCK
    assert engine.evaluate(result).action is Action.ALLOW


def test_rate_limited_calls_return_their_results(tmp_path: Path) -> None:
    text = rules(
        rule(
            'nome = "brake"\nazione = "blocca"\nstrumento = "echo"\n'
            "frequenza = { massimo = 2, secondi = 3600 }"
        )
    )
    live, _, _ = shield_with_rules(tmp_path, text)
    assert live.ask(request(1, "tools/list"))["result"]["tools"][0]["name"] == "echo"
    for index in (2, 3):
        answer = live.ask(call(index, "echo", {"text": "hi"}))
        assert answer["result"]["content"][0]["text"] == "hi"
    blocked = live.ask(call(4, "echo", {"text": "hi"}))
    assert blocked["error"]["code"] == SHIELD_BLOCKED
    live.close()


def test_rate_on_lists_or_results_is_flagged() -> None:
    text = rules(
        rule(
            'nome = "useless"\nazione = "blocca"\nfase = "elenco"\n'
            "frequenza = { massimo = 2, secondi = 60 }"
        )
    )
    assert ("warning", "rate_never_matches", 3) in [
        (issue.level.value, issue.code, issue.line) for issue in parse_rules(text, HOME).issues
    ]


@pytest.mark.skipif(not WINDOWS, reason="Job Objects exist only on Windows")
def test_stopping_a_cmd_launched_server_kills_the_whole_tree(tmp_path: Path) -> None:
    pid_file = tmp_path / "server.pid"
    command = launcher(tmp_path, STUBBORN, "stubborn", str(pid_file))
    live = LiveShield(command=(str(command),), grace=0.5)
    assert live.ask(request(1, "ping"))["id"] == 1
    pid = int(wait_for(pid_file))
    assert alive(pid)
    started = time.monotonic()
    live.close()
    assert time.monotonic() - started < 15
    assert gone(pid)


@pytest.mark.skipif(not WINDOWS, reason="process checks use Windows APIs")
def test_ctrl_c_stops_a_hand_started_shield_and_its_server(tmp_path: Path) -> None:
    pid_file = tmp_path / "server.pid"
    stubborn = tmp_path / "stubborn.py"
    stubborn.write_text(STUBBORN, encoding="utf-8")
    helper = tmp_path / "interrupt.py"
    helper.write_text(INTERRUPT, encoding="utf-8")
    command = [sys.executable, str(helper), str(pid_file)]
    command += [sys.executable, "-I", str(stubborn), str(pid_file)]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment(tmp_path),
    )
    assert process.stdin is not None
    assert process.stderr is not None
    try:
        process.wait(TIMEOUT)
    finally:
        process.kill()
        process.stdin.close()
    errors = process.stderr.read().decode("utf-8", "replace")
    assert "Scudo fermato" in errors
    assert "Traceback" not in errors
    assert gone(int(pid_file.read_text(encoding="utf-8")))


def test_local_drives_are_not_remote() -> None:
    system = os.environ.get("SYSTEMDRIVE", "C:")
    assert remote_drive(system) is False
    assert remote_drive("bad\x00drive") is False
    assert remote_drive("") is False


@pytest.mark.skipif(not WINDOWS, reason="Job Objects exist only on Windows")
def test_server_processes_are_contained(tmp_path: Path) -> None:
    process = ServerProcess.start(SERVER)
    try:
        assert process.contained
    finally:
        process.stop(1)


def test_cmd_arguments_are_quoted_for_cmd() -> None:
    assert cmd_quote("plain") == "plain"
    assert cmd_quote("a&b") == '"a&b"'
    assert cmd_quote('say "hi"') == '"say ""hi"""'
    assert cmd_quote("") == '""'
    assert cmd_quote("dir with space\\") == '"dir with space\\\\"'
    assert cmd_quote('a\\"b') == '"a\\\\""b"'
    line = command_line(["C:/tools/npx.CMD", "-y", "x&y"], windows=True)
    assert line == 'C:/tools/npx.CMD -y "x&y"'
    assert command_line(["node", "a&b"], windows=True) == ["node", "a&b"]
    assert command_line(["C:/tools/npx.cmd", "a&b"], windows=False) == ["C:/tools/npx.cmd", "a&b"]
    with pytest.raises(UnsafeArgumentError):
        command_line(["C:/tools/run.bat", "two\nlines"], windows=True)


@pytest.mark.skipif(not WINDOWS, reason="cmd.exe exists only on Windows")
def test_cmd_launchers_receive_arguments_exactly(tmp_path: Path) -> None:
    command = launcher(tmp_path, DUMP_ARGS, "dump")
    output = tmp_path / "args.json"
    process = ServerProcess.start([str(command), str(output), *TRICKY])
    assert process.stop(30) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == TRICKY


def short_name(path: Path) -> str | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_unicode_buffer(4096)
    if not kernel32.GetShortPathNameW(str(path), buffer, 4096):
        return None
    return buffer.value


@pytest.mark.skipif(not WINDOWS, reason="8.3 names exist only on Windows")
def test_short_names_cannot_bypass_path_rules(tmp_path: Path) -> None:
    folder = tmp_path / "averylongdirectoryname" / ".ssh"
    folder.mkdir(parents=True)
    (folder / "id_rsa").write_text("x", encoding="utf-8")
    short = short_name(folder / "id_rsa")
    if short is None or "~" not in short:
        pytest.skip("8.3 short names are disabled on this volume")
    long_text = str(folder / "id_rsa").replace("\\", "/")
    assert normalize_path(short, HOME) == normalize_path(long_text, HOME)
    pattern = str(tmp_path / "averylongdirectoryname" / ".ssh").replace("\\", "/") + "/**"
    text = rules(rule(f'nome = "ssh"\nazione = "blocca"\nargomento.percorso = "{pattern}"'))
    engine = Engine(ruleset(text), HOME)
    for value in (short, short.rsplit("\\", 1)[0] + "\\new_key"):
        context = Context(Phase.CALL, "fs", "tools/call", "read", {"path": value})
        assert engine.evaluate(context).action is Action.BLOCK, value


def test_tools_hidden_by_new_list_rules_cannot_be_called(tmp_path: Path) -> None:
    live, _, reports = shield_with_rules(tmp_path, None, "--list-changed")
    live.ask(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    assert live.ask(request(2, "tools/list"))["result"]["tools"][0]["name"] == "echo"
    directory = tmp_path / "data"
    write_rules(
        directory,
        rules(rule('nome = "hide echo"\nazione = "blocca"\nfase = "elenco"\nstrumento = "echo"')),
    )
    approve_rules(directory, HOME, RAW_PROTECTOR)
    live.send(call(3, "echo", {"text": "x"}))
    first = live.receive()
    assert first == {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    blocked = live.receive()
    assert blocked["id"] == 3
    assert "nascosto da una regola" in blocked["error"]["message"]
    assert live.ask(request(4, "tools/list"))["result"]["tools"] == []
    live.close()
    assert any("Regole attive: 1" in line for line in reports)


def test_no_list_changed_without_the_server_capability(tmp_path: Path) -> None:
    live, _, _ = shield_with_rules(tmp_path, None)
    live.ask(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    live.ask(request(2, "tools/list"))
    directory = tmp_path / "data"
    write_rules(
        directory,
        rules(rule('nome = "hide echo"\nazione = "blocca"\nfase = "elenco"\nstrumento = "echo"')),
    )
    approve_rules(directory, HOME, RAW_PROTECTOR)
    blocked = live.ask(call(3, "echo", {"text": "x"}))
    assert blocked["id"] == 3
    assert blocked["error"]["code"] == SHIELD_BLOCKED
    live.close()


def confirm_shield(
    tmp_path: Path, confirmer: Any, text: str, language: str = "it"
) -> tuple[LiveShield, Ledger, list[str]]:
    directory = tmp_path / "data"
    write_rules(directory, text)
    approve_rules(directory, HOME, RAW_PROTECTOR)
    ledger = Ledger(directory, RAW_PROTECTOR)
    reports: list[str] = []
    inspector = RulesInspector(
        server="fake",
        policy=PolicyWatcher(directory, HOME, RAW_PROTECTOR, interval=0).current,
        home=HOME,
        ledger=ledger,
        t=Translator(language),
        report=reports.append,
        confirm=confirmer,
    )
    return LiveShield(inspector=inspector), ledger, reports


ASK_ECHO = rules(rule('nome = "confirm"\nazione = "chiedi"\nstrumento = "echo"'))


def waiting(confirmer: FakeConfirmer, count: int = 1) -> None:
    deadline = time.monotonic() + TIMEOUT
    while len(confirmer.requests) < count:
        assert time.monotonic() < deadline
        time.sleep(0.02)


def cancel(request_id: int) -> bytes:
    return notification("notifications/cancelled", {"requestId": request_id})


def test_cancelled_request_waiting_for_confirmation_is_never_forwarded(tmp_path: Path) -> None:
    hold = threading.Event()
    confirmer = FakeConfirmer(Answer.ALLOW, hold=hold)
    live, ledger, reports = confirm_shield(tmp_path, confirmer, ASK_ECHO)
    live.send(call(1, "echo", {"text": "send it"}))
    waiting(confirmer)
    live.send(cancel(1))
    deadline = time.monotonic() + TIMEOUT
    shown = confirmer.requests[0].cancelled
    assert shown is not None
    while not shown.is_set():
        assert time.monotonic() < deadline
        time.sleep(0.02)
    hold.set()
    assert live.ask(request(2, "ping"))["id"] == 2
    live.close()
    assert answers(ledger) == ["cancelled"]
    assert not any("does not match" in line or "non corrisponde" in line for line in reports)
    assert any("annullata dal client" in line for line in reports)


def test_cancelled_requests_in_the_queue_skip_the_window(tmp_path: Path) -> None:
    hold = threading.Event()
    confirmer = FakeConfirmer(Answer.ALLOW, hold=hold)
    live, ledger, _ = confirm_shield(tmp_path, confirmer, ASK_ECHO)
    live.send(call(1, "echo", {"text": "first"}))
    waiting(confirmer)
    live.send(call(2, "echo", {"text": "second"}))
    live.send(call(3, "echo", {"text": "third"}))
    time.sleep(0.3)
    live.send(cancel(2))
    live.send(cancel(3))
    time.sleep(0.5)
    hold.set()
    assert live.receive()["result"]["content"][0]["text"] == "first"
    assert live.ask(request(9, "ping"))["id"] == 9
    live.close()
    assert [asked.details for asked in confirmer.requests] == ["text: first"]
    assert sorted(answers(ledger)) == ["allow", "cancelled", "cancelled"]


def window_script(tmp_path: Path, pid_file: Path) -> list[str]:
    path = tmp_path / "slow_window.py"
    path.write_text(
        "import os, sys, time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "sys.stdin.buffer.read()\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    return [sys.executable, "-I", str(path)]


def test_cancelling_closes_the_confirmation_window(tmp_path: Path) -> None:
    pid_file = tmp_path / "window.pid"
    confirmer = WindowConfirmer(window_script(tmp_path, pid_file), margin=0)
    cancelled = threading.Event()
    asked = ConfirmRequest("srv", "tools/call", "t", (), "", "it", 30, cancelled=cancelled)
    result: list[Answer] = []
    worker = threading.Thread(target=lambda: result.append(confirmer(asked)), daemon=True)
    worker.start()
    pid = int(wait_for(pid_file))
    cancelled.set()
    worker.join(10)
    assert result == [Answer.UNAVAILABLE]
    if WINDOWS:
        assert gone(pid)


def test_shutdown_closes_open_confirmation_windows(tmp_path: Path) -> None:
    pid_file = tmp_path / "window.pid"
    confirmer = WindowConfirmer(window_script(tmp_path, pid_file), margin=0)
    live, ledger, _ = confirm_shield(tmp_path, confirmer, ASK_ECHO)
    live.send(call(1, "echo", {"text": "x"}))
    pid = int(wait_for(pid_file))
    started = time.monotonic()
    live.close()
    assert time.monotonic() - started < 15
    if WINDOWS:
        assert gone(pid)
    assert answers(ledger) == ["cancelled"]


def test_confirmation_waits_less_than_a_client_request_timeout() -> None:
    assert CONFIRM_SECONDS < 60
    assert parse_answer(b'{"answer": "cancelled"}') is Answer.UNAVAILABLE


def test_confirmation_details_show_the_matched_field_first(tmp_path: Path) -> None:
    confirmer = FakeConfirmer(Answer.BLOCK)
    text = rules(
        rule('nome = "ssh"\nazione = "chiedi"\nargomento.percorso = "~/.ssh/**"'),
    )
    live, _, _ = confirm_shield(tmp_path, confirmer, text)
    arguments = {
        "note": "x" * 2500,
        "count": 3,
        "body": "line one\nline two\u202e",
        "path": "~/.ssh/id_rsa",
    }
    live.ask(call(1, "echo", arguments))
    live.close()
    details = confirmer.requests[0].details
    assert details.startswith("path: ~/.ssh/id_rsa\n")
    assert "body: line one\n  line two\\u202e" in details
    assert "count: 3" in details
    assert "note: " + "x" * 10 in details
    assert len(details) <= MAX_DETAILS


def test_window_keeps_real_line_breaks() -> None:
    original = ConfirmRequest("srv", "tools/call", "t", (), "a: 1\nb: two\r\nc\u202e", "it", 30)
    parsed = parse_request(original.to_json())
    assert parsed.details == "a: 1\nb: two\nc\\u202e"


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"message": "Which version should I pin?"}, None),
        ({"message": "Pin the dependency to 1.2.3"}, None),
        ({"message": "Enter your PIN"}, "PIN"),
        ({"message": "Inserisci il codice PIN"}, "codice PIN"),
        ({"requestedSchema": {"properties": {"pinCode": {"type": "string"}}}}, "pinCode"),
        ({"requestedSchema": {"properties": {"otp_code": {"type": "string"}}}}, "otp_code"),
        (
            {"requestedSchema": {"properties": {"code": {"title": "One-time password"}}}},
            "One-time password",
        ),
        ({"requestedSchema": {"properties": {"pinned_version": {"type": "string"}}}}, None),
        ({"mode": "url", "message": "Sign in to reset your password", "url": "https://x"}, None),
    ],
)
def test_password_requests_look_only_at_what_the_user_is_asked(
    params: dict[str, Any], expected: str | None
) -> None:
    assert credential_request(params) == expected


def test_only_elicitations_are_checked_for_passwords() -> None:
    sampling = {"messages": [{"role": "user", "content": {"text": "where is the password?"}}]}
    assert elicitations("sampling/createMessage", sampling) == []
    assert elicitations("elicitation/create", {"message": "x"}) == [{"message": "x"}]
    requests = {
        "login": {"method": "elicitation/create", "params": {"message": "Enter your password"}},
        "think": {"method": "sampling/createMessage", "params": sampling},
    }
    assert input_elicitations(requests) == [{"message": "Enter your password"}]
    assert input_elicitations(["not", "a", "map"]) == []


def english(text: str) -> list[tuple[str, int | None, str]]:
    t = Translator("en")
    return [
        (issue.level.value, issue.line, t(f"shield_rules.{issue.code}", **issue.params))
        for issue in parse_rules(text, HOME).issues
    ]


def test_english_files_get_english_key_names_and_options() -> None:
    found = english('version = 1\n\n[protections]\nanalysis = "hgih"\n')
    assert found == [
        (
            "error",
            4,
            'Value "hgih" is not valid for "analysis": use off, critical, high, medium.',
        )
    ]
    found = english('version = 1\n[[rule]]\nname = "a"\naction = "block"\nargument.colour = 1\n')
    assert ("error", 5, 'Unknown key "colour" in argument.') in found
    found = english('default = "allow"\n')
    assert found == [("error", 1, 'The file must start with "version = 1".')]


def test_italian_files_keep_italian_names() -> None:
    issues = parse_rules('versione = 1\n[protezioni]\nanalisi = "x"\n', HOME).issues
    assert issues[0].params["key"] == "analisi"
    assert issues[0].params["options"] == "spento, critico, alto, medio"
    assert issues[0].line == 3


def test_errors_inside_sub_tables_point_to_the_key() -> None:
    text = (
        'version = 1\n[[rule]]\nname = "a"\naction = "block"\n\n'
        '[rule.argument]\nfield = "url"\npath = 3\n'
    )
    issues = parse_rules(text, HOME).issues
    assert [(i.code, i.line, i.params.get("key")) for i in issues] == [("not_strings", 8, "path")]
    text = 'versione = 1\ncolore = 1\n[[regola]]\nnome = "a"\nazione = "blocca"\nstrumento = "x"\n'
    issues = parse_rules(text, HOME).issues
    assert [(i.level, i.code, i.line) for i in issues] == [(Level.ERROR, "unknown_key", 2)]


def test_english_block_messages_use_plain_quotes(tmp_path: Path) -> None:
    text = 'version = 1\n[[rule]]\nname = "confirm"\naction = "ask"\ntool = "echo"\n'
    live, _, _ = confirm_shield(tmp_path, None, text, language="en")
    answer = live.ask(call(1, "echo", {"text": "x"}))
    live.close()
    assert 'Rule: "confirm".' in answer["error"]["message"]
    assert "«" not in answer["error"]["message"]
