from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import IO

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.redact import redact_args
from guardia.secure_store import KeyStoreError
from guardia.shield.framing import MAX_MESSAGE_BYTES, FrameWriter
from guardia.shield.messages import Direction
from guardia.shield.process import GRACE_SECONDS, LaunchError, ServerProcess
from guardia.shield.proxy import Inspector, Outcome, Passthrough, Proxy, Report

EXIT_SHIELD_FAILED = 3
MAX_LOGGED_ARGS = 40
NAME_WIDTH = 80


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
    try:
        process = ServerProcess.start(options.command)
    except LaunchError as exc:
        report(t("shield.launch_failed", error=safe_text(str(exc), 200)))
        _record(ledger, "shield_stop", {"server": name, "launch_failed": True})
        return EXIT_SHIELD_FAILED
    report(t("shield.started", server=name, pid=process.pid))
    started = time.monotonic()
    proxy = Proxy(
        to_client=FrameWriter(client_out),
        to_server=FrameWriter(process.stdin),
        inspector=inspector or Passthrough(),
        report=report,
        t=t,
        limit=options.limit,
    )

    def client_side() -> None:
        proxy.pump(Direction.TO_SERVER, client_in)
        process.stop(options.grace)

    threading.Thread(target=client_side, name="guardia-shield-client", daemon=True).start()
    proxy.pump(Direction.TO_CLIENT, process.stdout)
    code = process.stop(options.grace)
    summary = _summary(proxy, code, time.monotonic() - started)
    failure = _record(ledger, "shield_stop", {"server": name, **summary})
    if failure is not None:
        report(t("shield.ledger_failed_stop", error=failure))
    report(t("shield.stopped", server=name, **summary))
    return code
