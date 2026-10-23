from __future__ import annotations

import enum
import json
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from guardia.display import safe_text
from guardia.shield.process import run_confirmation

CONFIRM_SECONDS = 60
STARTUP_GRACE_SECONDS = 20
MAX_REQUEST_BYTES = 64 * 1024
MAX_REASONS = 8
MAX_FIELD = 200
MAX_DETAILS = 2000
LANGUAGES = frozenset({"it", "en"})


class Answer(enum.StrEnum):
    ALLOW = "allow"
    ALLOW_REMEMBER = "allow_remember"
    BLOCK = "block"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ConfirmRequest:
    server: str
    method: str
    tool: str
    reasons: tuple[str, ...]
    details: str
    language: str = "it"
    seconds: int = CONFIRM_SECONDS

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "server": self.server,
                "method": self.method,
                "tool": self.tool,
                "reasons": list(self.reasons),
                "details": self.details,
                "language": self.language,
                "seconds": self.seconds,
            },
            ensure_ascii=False,
        ).encode("utf-8")


class RequestError(Exception):
    pass


def _field(value: object, limit: int = MAX_FIELD) -> str:
    if not isinstance(value, str):
        raise RequestError("field")
    return safe_text(value, limit)


def parse_request(data: bytes) -> ConfirmRequest:
    if len(data) > MAX_REQUEST_BYTES:
        raise RequestError("size")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RequestError("json") from exc
    if not isinstance(document, dict):
        raise RequestError("object")
    reasons = document.get("reasons")
    seconds = document.get("seconds")
    language = document.get("language")
    if not isinstance(reasons, list) or len(reasons) > MAX_REASONS:
        raise RequestError("reasons")
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 5 <= seconds <= 600:
        raise RequestError("seconds")
    if language not in LANGUAGES:
        raise RequestError("language")
    return ConfirmRequest(
        server=_field(document.get("server")),
        method=_field(document.get("method")),
        tool=_field(document.get("tool")),
        reasons=tuple(_field(reason, 400) for reason in reasons),
        details=_field(document.get("details"), MAX_DETAILS),
        language=str(language),
        seconds=seconds,
    )


def answer_json(answer: Answer) -> bytes:
    return json.dumps({"answer": answer.value}).encode("ascii")


def parse_answer(data: bytes | None) -> Answer:
    if not data:
        return Answer.UNAVAILABLE
    try:
        document = json.loads(data.decode("utf-8"))
        return Answer(document["answer"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        return Answer.UNAVAILABLE


def confirm_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "scudo", "conferma"]
    return [sys.executable, "-m", "guardia", "scudo", "conferma"]


Confirmer = Callable[[ConfirmRequest], Answer]


class WindowConfirmer:
    def __init__(
        self, command: Sequence[str] | None = None, margin: float = STARTUP_GRACE_SECONDS
    ) -> None:
        self._command = list(command) if command is not None else confirm_command()
        self._margin = margin
        self._lock = threading.Lock()

    def __call__(self, request: ConfirmRequest) -> Answer:
        with self._lock:
            output = run_confirmation(
                self._command, request.to_json(), request.seconds + self._margin
            )
        return parse_answer(output)
