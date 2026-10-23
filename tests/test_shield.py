from __future__ import annotations

import io
import json
import os
import queue
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from guardia.cli import main, split_command
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.framing import FrameStatus, FrameWriter, read_frame
from guardia.shield.messages import (
    SHIELD_BLOCKED,
    Direction,
    Message,
    MessageError,
    MessageKind,
    Problem,
    parse_message,
)
from guardia.shield.proxy import Decision, Passthrough, Proxy, Verdict
from guardia.shield.runner import EXIT_SHIELD_FAILED, ShieldOptions, run_shield
from guardia.shield.session import Admission, Session

FAKE = Path(__file__).parent / "corpus" / "shield" / "fake_server.py"
SERVER = (sys.executable, "-I", str(FAKE))
TIMEOUT = 15


def encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message).encode("utf-8")


def request(request_id: object, method: str, params: dict[str, Any] | None = None) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return encode(message)


def notification(method: str, params: dict[str, Any] | None = None) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return encode(message)


class LiveShield:
    def __init__(
        self,
        *flags: str,
        inspector: Any = None,
        ledger: Ledger | None = None,
        grace: float = 5.0,
        limit: int = 32 * 1024 * 1024,
        command: tuple[str, ...] | None = None,
    ) -> None:
        read_in, write_in = os.pipe()
        read_out, write_out = os.pipe()
        self._client_in = os.fdopen(read_in, "rb")
        self._to_shield = os.fdopen(write_in, "wb")
        self._client_out = os.fdopen(write_out, "wb")
        self._from_shield = os.fdopen(read_out, "rb")
        self.reports: list[str] = []
        self.code: int | None = None
        self.proxy_options = ShieldOptions(
            "fake", command or (*SERVER, *flags), limit=limit, grace=grace
        )
        self._inspector = inspector
        self._ledger = ledger
        self._messages: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._runner = threading.Thread(target=self._run, daemon=True)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._runner.start()
        self._reader.start()

    def _run(self) -> None:
        try:
            self.code = run_shield(
                self.proxy_options,
                t=Translator("en"),
                client_in=self._client_in,
                client_out=self._client_out,
                report=self.reports.append,
                ledger=self._ledger,
                inspector=self._inspector,
            )
        finally:
            self._client_out.close()

    def _read(self) -> None:
        for line in self._from_shield:
            if line.strip():
                self._messages.put(json.loads(line))
        self._messages.put(None)

    def send(self, data: bytes) -> None:
        self._to_shield.write(data + b"\n")
        self._to_shield.flush()

    def receive(self, timeout: float = TIMEOUT) -> dict[str, Any]:
        message = self._messages.get(timeout=timeout)
        assert message is not None, self.reports
        return message

    def ask(self, data: bytes) -> dict[str, Any]:
        self.send(data)
        return self.receive()

    def close(self) -> int | None:
        self._to_shield.close()
        self._runner.join(TIMEOUT * 2)
        assert not self._runner.is_alive()
        return self.code

    def finished(self, timeout: float = TIMEOUT) -> int | None:
        self._runner.join(timeout)
        return self.code


class RaisingInspector:
    def inspect(self, direction: Direction, message: Message, pending: object) -> Decision:
        if message.method == "tools/call":
            raise RuntimeError("boom")
        return Passthrough().inspect(direction, message, None)


class NoneInspector:
    def inspect(self, direction: Direction, message: Message, pending: object) -> Any:
        return None if message.method == "tools/call" else Decision(Verdict.FORWARD)


class RejectToolLists:
    def inspect(self, direction: Direction, message: Message, pending: object) -> Decision:
        result = message.payload.get("result")
        if direction is Direction.TO_CLIENT and isinstance(result, dict) and "tools" in result:
            return Decision(Verdict.REJECT, reason="test")
        return Decision(Verdict.FORWARD)


class ReplaceArguments:
    def inspect(self, direction: Direction, message: Message, pending: object) -> Decision:
        if message.method != "tools/call":
            return Decision(Verdict.FORWARD)
        payload = json.loads(json.dumps(message.payload))
        payload["params"]["arguments"]["text"] = "[REDACTED]"
        return Decision(Verdict.FORWARD, Message(message.kind, payload, message.id, message.method))


def test_parse_valid_messages() -> None:
    call = parse_message(request(1, "tools/call", {"name": "echo"}))
    assert (call.kind, call.id, call.method) == (MessageKind.REQUEST, 1, "tools/call")
    note = parse_message(notification("notifications/initialized"))
    assert note.kind is MessageKind.NOTIFICATION
    answer = parse_message(b'{"jsonrpc":"2.0","id":"a","result":{"ok":true}}')
    assert (answer.kind, answer.id) == (MessageKind.RESPONSE, "a")
    failure = parse_message(b'{"jsonrpc":"2.0","id":null,"error":{"code":-1,"message":"x"}}')
    assert failure.kind is MessageKind.RESPONSE
    assert parse_message('{"jsonrpc":"2.0","method":"città ✓"}'.encode()).encode() == (
        '{"jsonrpc":"2.0","method":"città ✓"}'.encode()
    )


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        (b"\xff\xfe", Problem.NOT_UTF8),
        (b"not json", Problem.NOT_JSON),
        (b'{"jsonrpc":"2.0","method":"a","method":"b"}', Problem.DUPLICATE_KEYS),
        (b"[" * 5000 + b"]" * 5000, Problem.TOO_DEEP),
        (
            b'{"jsonrpc":"2.0","id":1,"params":' + b'{"a":' * 150 + b"1" + b"}" * 151,
            Problem.TOO_DEEP,
        ),
        (b'[{"jsonrpc":"2.0","method":"a"}]', Problem.BATCH),
        (b'"text"', Problem.NOT_OBJECT),
        (b'{"jsonrpc":"1.0","id":1,"method":"a"}', Problem.BAD_VERSION),
        (b'{"jsonrpc":"2.0","id":true,"method":"a"}', Problem.BAD_ID),
        (b'{"jsonrpc":"2.0","id":1.5,"method":"a"}', Problem.BAD_ID),
        (b'{"jsonrpc":"2.0","id":null,"method":"a"}', Problem.BAD_ID),
        (b'{"jsonrpc":"2.0","id":1,"method":""}', Problem.BAD_METHOD),
        (b'{"jsonrpc":"2.0","id":1,"method":"a","params":[1]}', Problem.BAD_PARAMS),
        (b'{"jsonrpc":"2.0","id":1,"method":"a","result":{}}', Problem.BAD_METHOD),
        (
            b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}',
            Problem.BAD_RESPONSE,
        ),
        (b'{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"x"}}', Problem.BAD_RESPONSE),
        (b'{"jsonrpc":"2.0","id":1,"result":NaN}', Problem.NOT_JSON),
        (b'{"jsonrpc":"2.0","result":{}}', Problem.BAD_RESPONSE),
    ],
)
def test_parse_rejects_invalid_messages(data: bytes, problem: Problem) -> None:
    with pytest.raises(MessageError) as caught:
        parse_message(data)
    assert caught.value.problem is problem


def test_framing_limits_and_line_endings() -> None:
    stream = io.BytesIO(b"\r\n\n" + b"x" * 50 + b"\nshort\r\nlast")
    oversized = read_frame(stream, limit=10)
    assert (oversized.status, oversized.size) == (FrameStatus.OVERSIZED, 51)
    assert read_frame(stream, limit=10).data == b"short"
    assert read_frame(stream, limit=10).data == b"last"
    assert read_frame(stream, limit=10).status is FrameStatus.END


def proxy_with_buffers() -> tuple[Proxy, io.BytesIO, io.BytesIO]:
    to_client, to_server = io.BytesIO(), io.BytesIO()
    proxy = Proxy(
        to_client=FrameWriter(to_client),
        to_server=FrameWriter(to_server),
        inspector=Passthrough(),
        report=lambda _: None,
        t=Translator("en"),
    )
    return proxy, to_client, to_server


def lines(buffer: io.BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def test_duplicate_in_flight_id_is_rejected() -> None:
    proxy, to_client, to_server = proxy_with_buffers()
    proxy.pump(
        Direction.TO_SERVER, io.BytesIO(request(1, "ping") + b"\n" + request(1, "ping") + b"\n")
    )
    assert len(lines(to_server)) == 1
    errors = lines(to_client)
    assert errors[0]["id"] == 1
    assert errors[0]["error"]["code"] == -32600


def test_cancellation_frees_the_pending_request() -> None:
    proxy, _, _ = proxy_with_buffers()
    proxy.pump(Direction.TO_SERVER, io.BytesIO(request(7, "tools/call") + b"\n"))
    assert proxy.session.in_flight() == 1
    cancel = notification("notifications/cancelled", {"requestId": 7})
    proxy.pump(Direction.TO_SERVER, io.BytesIO(cancel + b"\n"))
    assert proxy.session.in_flight() == 0


def test_session_limits_pending_requests() -> None:
    session = Session()
    message = parse_message(request("same", "ping"))
    assert session.begin(Direction.TO_SERVER, message) is Admission.ACCEPTED
    assert session.begin(Direction.TO_SERVER, message) is Admission.DUPLICATE
    assert session.begin(Direction.TO_CLIENT, message) is Admission.ACCEPTED
    assert (
        session.begin(Direction.TO_SERVER, parse_message(request(1, "ping"))) is Admission.ACCEPTED
    )
    assert (
        session.begin(Direction.TO_SERVER, parse_message(request("1", "ping")))
        is Admission.ACCEPTED
    )


def test_protocol_2025_initialize_and_tools() -> None:
    shield = LiveShield()
    init = shield.ask(
        request(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    )
    assert init["result"]["protocolVersion"] == "2025-11-25"
    shield.send(notification("notifications/initialized"))
    tools = shield.ask(request(2, "tools/list"))
    assert tools["result"]["tools"][0]["name"] == "echo"
    text = "città ✓ \u202e"
    call = shield.ask(request(3, "tools/call", {"name": "echo", "arguments": {"text": text}}))
    assert call["result"]["content"][0]["text"] == text
    assert shield.close() == 0
    assert any("7 messages forwarded, 0 blocked, 0 dropped" in line for line in shield.reports)


def test_protocol_2026_discover_and_meta() -> None:
    shield = LiveShield()
    discover = shield.ask(request("d", "server/discover", {}))
    assert discover["result"]["supportedVersions"] == ["2026-07-28", "2025-11-25"]
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    call = shield.ask(
        request("c", "tools/call", {"name": "echo", "arguments": {"text": "ok"}, "_meta": meta})
    )
    assert call["result"]["resultType"] == "complete"
    assert shield.close() == 0
    assert any("exit code 0" in line for line in shield.reports)


def test_server_noise_is_dropped() -> None:
    shield = LiveShield("--noise")
    assert shield.ask(request(1, "ping"))["id"] == 1
    shield.close()
    assert any("not_json" in line for line in shield.reports)


def test_spoofed_response_is_dropped() -> None:
    shield = LiveShield("--spoof")
    assert shield.ask(request(5, "ping")) == {"jsonrpc": "2.0", "id": 5, "result": {}}
    shield.close()
    assert any("does not match any request" in line for line in shield.reports)


def test_duplicate_keys_from_the_server_never_reach_the_client() -> None:
    shield = LiveShield("--duplicate-keys")
    shield.send(request(1, "tools/list"))
    assert shield.ask(request(2, "ping"))["id"] == 2
    shield.close()
    assert any("duplicate_keys" in line for line in shield.reports)


def test_invalid_client_messages() -> None:
    shield = LiveShield()
    answer = shield.ask(b'{"jsonrpc":"1.0","id":5,"method":"ping"}')
    assert answer["id"] == 5
    assert answer["error"]["code"] == -32600
    shield.send(b'[{"jsonrpc":"2.0","id":6,"method":"ping"}]')
    shield.send(b"garbage")
    assert shield.ask(request(7, "ping"))["id"] == 7
    shield.close()
    assert any("batch" in line for line in shield.reports)
    assert any("not_json" in line for line in shield.reports)


def test_lone_surrogates_are_rejected_instead_of_crashing_the_shield() -> None:
    shield = LiveShield("--surrogate")
    shield.send(rb'{"jsonrpc":"2.0","method":"notifications/x","params":{"a":"\udc00"}}')
    answer = shield.ask(rb'{"jsonrpc":"2.0","id":3,"method":"ping","params":{"a":"\ud800"}}')
    assert answer["id"] == 3
    assert answer["error"]["code"] == -32600
    assert shield.ask(request(4, "ping"))["id"] == 4
    shield.close()
    assert sum("not_utf8" in line for line in shield.reports) == 3


def test_server_request_and_client_response() -> None:
    shield = LiveShield("--server-request")
    shield.send(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    received = [shield.receive(), shield.receive()]
    sampling = next(m for m in received if m.get("method") == "sampling/createMessage")
    shield.send(encode({"jsonrpc": "2.0", "id": sampling["id"], "result": {"role": "assistant"}}))
    echo = shield.receive()
    assert echo["params"] == {"received": "s1"}
    shield.close()


@pytest.mark.parametrize("inspector", [RaisingInspector(), NoneInspector()])
def test_inspector_failures_block_the_message(inspector: Any) -> None:
    shield = LiveShield(inspector=inspector)
    answer = shield.ask(request(1, "tools/call", {"name": "echo", "arguments": {"text": "x"}}))
    assert answer["error"]["code"] == SHIELD_BLOCKED
    assert answer["error"]["message"] == "Blocked by Guardia MCP Shield."
    assert shield.ask(request(2, "ping"))["id"] == 2
    shield.close()
    assert any("blocked for safety" in line for line in shield.reports)


def test_rejected_response_becomes_an_error_for_the_requester() -> None:
    shield = LiveShield(inspector=RejectToolLists())
    answer = shield.ask(request("t", "tools/list"))
    assert answer["id"] == "t"
    assert answer["error"]["code"] == SHIELD_BLOCKED
    shield.close()


def test_replacement_is_what_the_server_receives() -> None:
    shield = LiveShield(inspector=ReplaceArguments())
    answer = shield.ask(request(1, "tools/call", {"name": "echo", "arguments": {"text": "secret"}}))
    assert answer["result"]["content"][0]["text"] == "[REDACTED]"
    shield.close()


def test_oversized_messages_are_dropped_both_ways() -> None:
    shield = LiveShield("--huge", limit=4096)
    shield.send(request(1, "tools/call", {"name": "echo", "arguments": {"size": 10_000}}))
    shield.send(request(2, "tools/call", {"name": "echo", "arguments": {"text": "y" * 8000}}))
    assert shield.ask(request(3, "ping"))["id"] == 3
    shield.close()
    assert sum("over the limit" in line for line in shield.reports) == 2


def test_server_exit_code_is_returned() -> None:
    shield = LiveShield()
    shield.send(request(1, "exit"))
    assert shield.finished() == 7


def test_stubborn_server_is_stopped_after_the_grace_period() -> None:
    shield = LiveShield("--stubborn", grace=0.5)
    assert shield.ask(request(1, "ping"))["id"] == 1
    started = time.monotonic()
    code = shield.close()
    assert time.monotonic() - started < 10
    assert code != 0


def test_missing_program_fails_closed(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "data", RAW_PROTECTOR)
    shield = LiveShield(command=("guardia-program-that-does-not-exist",), ledger=ledger)
    assert shield.finished() == EXIT_SHIELD_FAILED
    assert any("Cannot start the server" in line for line in shield.reports)
    events = [record["event"] for record in ledger.records()]
    assert events == ["shield_start", "shield_stop"]


def test_unwritable_ledger_prevents_the_start(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_text("not a folder", encoding="utf-8")
    shield = LiveShield(ledger=Ledger(blocker, RAW_PROTECTOR))
    assert shield.finished() == EXIT_SHIELD_FAILED
    assert not any("Shield active" in line for line in shield.reports)
    assert any("server is not started" in line for line in shield.reports)


def test_ledger_records_the_session_with_redacted_command(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "data", RAW_PROTECTOR)
    token = "ghp_" + "A1" * 18
    shield = LiveShield("--token", token, ledger=ledger)
    shield.ask(request(1, "initialize", {"protocolVersion": "2025-11-25"}))
    shield.close()
    records = list(ledger.records())
    assert [r["event"] for r in records] == ["shield_start", "shield_stop"]
    assert token not in json.dumps(records)
    assert "[REDACTED]" in records[0]["data"]["command"]
    stop = records[1]["data"]
    assert stop["forwarded"] == 2
    assert stop["exit_code"] == 0
    assert "2025-11-25" in stop["protocol_versions"]
    assert ledger.verify().intact


def test_concurrent_processes_keep_the_ledger_chain(tmp_path: Path) -> None:
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from guardia.ledger import Ledger\n"
        "from guardia.secure_store import RAW_PROTECTOR\n"
        "ledger = Ledger(Path(sys.argv[1]), RAW_PROTECTOR)\n"
        "for index in range(25):\n"
        "    ledger.append('shield_start', {'worker': sys.argv[2], 'index': index})\n"
    )
    directory = tmp_path / "data"
    workers = [
        subprocess.Popen([sys.executable, "-c", script, str(directory), str(n)]) for n in range(4)
    ]
    assert [worker.wait(60) for worker in workers] == [0, 0, 0, 0]
    verification = Ledger(directory, RAW_PROTECTOR).verify()
    assert verification.records == 100
    assert verification.intact, verification.issues


def test_split_command() -> None:
    assert split_command(["scudo", "--server", "x", "--", "npx", "-y", "pkg"]) == (
        ["scudo", "--server", "x"],
        ["npx", "-y", "pkg"],
    )
    assert split_command(["scan", "--", "x"]) == (["scan", "--", "x"], [])
    assert split_command(["scudo"]) == (["scudo"], [])


def test_cli_without_command_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scudo", "--lingua", "it"]) == 2
    assert "Manca il comando del server" in capsys.readouterr().err


def test_cli_shield_end_to_end(tmp_path: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONIOENCODING", "PYTHONUTF8"}
    }
    environment.update(GUARDIA_LANG="it", LOCALAPPDATA=str(tmp_path))
    process = subprocess.run(
        [sys.executable, "-m", "guardia", "scudo", "--senza-registro", "--", *SERVER],
        input=request(1, "initialize", {"protocolVersion": "2025-11-25"})
        + b"\n"
        + request(2, "ping")
        + b"\n",
        capture_output=True,
        timeout=60,
        env=environment,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    output = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    assert [message["id"] for message in output] == [1, 2]
    errors = process.stderr.decode("utf-8")
    assert "[Guardia MCP] Scudo attivo per «python»" in errors
    assert "4 messaggi inoltrati, 0 bloccati, 0 scartati, codice di uscita 0" in errors
    assert "Scudo fermato" in errors


def round_trips(send: Any, receive: Any, count: int) -> list[float]:
    timings = []
    for index in range(count):
        started = time.perf_counter()
        send(request(index, "ping"))
        assert receive()["id"] == index
        timings.append(time.perf_counter() - started)
    return timings


def test_latency_overhead_is_small() -> None:
    direct = subprocess.Popen(SERVER, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert direct.stdin is not None
    assert direct.stdout is not None
    direct_in, direct_out = direct.stdin, direct.stdout

    def direct_send(data: bytes) -> None:
        direct_in.write(data + b"\n")
        direct_in.flush()

    def direct_receive() -> dict[str, Any]:
        message: dict[str, Any] = json.loads(direct_out.readline())
        return message

    baseline = round_trips(direct_send, direct_receive, 300)
    direct_in.close()
    direct.wait(10)
    shield = LiveShield()
    shielded = round_trips(shield.send, shield.receive, 300)
    shield.close()
    overhead = statistics.median(shielded) - statistics.median(baseline)
    print(
        f"\nlatency median direct={statistics.median(baseline) * 1000:.3f} ms "
        f"shield={statistics.median(shielded) * 1000:.3f} ms overhead={overhead * 1000:.3f} ms"
    )
    assert overhead < 0.010
