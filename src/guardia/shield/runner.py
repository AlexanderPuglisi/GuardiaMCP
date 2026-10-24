from __future__ import annotations

import contextlib
import io
import signal
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.redact import redact_args
from guardia.secure_store import KeyStoreError
from guardia.shield.framing import MAX_MESSAGE_BYTES, FrameWriter
from guardia.shield.messages import Direction, Message
from guardia.shield.process import (
    GRACE_SECONDS,
    LaunchError,
    ServerProcess,
    UnsafeArgumentError,
)
from guardia.shield.proxy import Inspector, Outcome, Passthrough, Proxy, Report

EXIT_SHIELD_FAILED = 3
MAX_LOGGED_ARGS = 40
NAME_WIDTH = 80
WAIT_STEP_SECONDS = 0.25
SETTLE_SECONDS = 5.0
LARGEST_EXIT_CODE = 0x7FFFFFFF


@dataclass(frozen=True, slots=True)
class ShieldOptions:
    server: str
    command: tuple[str, ...]
    limit: int = MAX_MESSAGE_BYTES
    grace: float = GRACE_SECONDS


def _record(ledger: Ledger | None, event: str, data: dict[str, object]) -> str | None:
    if ledger is None:
        return None
    try:
        ledger.append(event, data)
    except (OSError, KeyStoreError) as exc:
        return safe_text(str(exc) or type(exc).__name__, 200)
    return None


def _summary(proxy: Proxy, code: int, seconds: float) -> dict[str, object]:
    return {
        "exit_code": code,
        "seconds": round(seconds, 1),
        "forwarded": proxy.total(Outcome.FORWARDED),
        "blocked": proxy.total(Outcome.REJECTED),
        "dropped": proxy.total(
            Outcome.DROPPED, Outcome.MALFORMED, Outcome.OVERSIZED, Outcome.UNSOLICITED
        ),
        "protocol_versions": sorted(proxy.session.versions)[:10],
    }


def exit_status(code: int) -> int:
    return code - (1 << 32) if code > LARGEST_EXIT_CODE else code


def _private_reader(stream: IO[bytes]) -> IO[bytes]:
    standard: object = getattr(sys.stdin, "buffer", None)
    if stream is not standard:
        return stream
    try:
        if stream.isatty():
            return stream
        descriptor = stream.fileno()
    except (OSError, ValueError):
        return stream
    return io.BufferedReader(io.FileIO(descriptor, "rb", closefd=False))


def _wait(finished: threading.Event) -> bool:
    try:
        while not finished.wait(WAIT_STEP_SECONDS):
            pass
    except KeyboardInterrupt:
        with contextlib.suppress(ValueError):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        return True
    return False


def _launch(
    options: ShieldOptions, t: Translator, report: Report, ledger: Ledger | None, name: str
) -> ServerProcess | None:
    try:
        return ServerProcess.start(options.command)
    except UnsafeArgumentError:
        report(t("shield.unsafe_argument"))
    except LaunchError as exc:
        report(t("shield.launch_failed", error=safe_text(str(exc), 200)))
    _record(ledger, "shield_stop", {"server": name, "launch_failed": True})
    return None


def run_shield(
    options: ShieldOptions,
    *,
    t: Translator,
    client_in: IO[bytes],
    client_out: IO[bytes],
    report: Report,
    ledger: Ledger | None,
    inspector: Inspector | None = None,
) -> int:
    name = safe_text(options.server, NAME_WIDTH)
    command = [safe_text(part, 200) for part in redact_args(list(options.command))]
    failure = _record(
        ledger, "shield_start", {"server": name, "command": command[:MAX_LOGGED_ARGS]}
    )
    if failure is not None:
        report(t("shield.ledger_failed", error=failure))
        return EXIT_SHIELD_FAILED
    process = _launch(options, t, report, ledger, name)
    if process is None:
        return EXIT_SHIELD_FAILED
    report(t("shield.started", server=name, pid=process.pid))
    started = time.monotonic()
    to_client = FrameWriter(client_out)
    proxy = Proxy(
        to_client=to_client,
        to_server=FrameWriter(process.stdin),
        inspector=inspector or Passthrough(),
        report=report,
        t=t,
        limit=options.limit,
    )
    attach: Callable[[Callable[[Message], bool]], None] | None = getattr(inspector, "attach", None)
    if attach is not None:
        attach(proxy.send_to_client)
    reader = _private_reader(client_in)
    finished = threading.Event()

    def client_side() -> None:
        proxy.pump(Direction.TO_SERVER, reader)
        process.stop(options.grace)

    def server_side() -> None:
        proxy.pump(Direction.TO_CLIENT, process.stdout)
        finished.set()

    threading.Thread(target=client_side, name="guardia-shield-client", daemon=True).start()
    threading.Thread(target=server_side, name="guardia-shield-server", daemon=True).start()
    interrupted = _wait(finished)
    code = process.stop(0 if interrupted else options.grace)
    finished.wait(options.grace)
    proxy.cancel_waiting(SETTLE_SECONDS)
    to_client.close()
    summary = _summary(proxy, code, time.monotonic() - started)
    if interrupted:
        summary["interrupted"] = True
    failure = _record(ledger, "shield_stop", {"server": name, **summary})
    if failure is not None:
        report(t("shield.ledger_failed_stop", error=failure))
    report(t("shield.stopped", server=name, **summary))
    return exit_status(code)
