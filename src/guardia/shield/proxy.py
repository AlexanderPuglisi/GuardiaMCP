from __future__ import annotations

import enum
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import IO, Protocol

from guardia.i18n import Translator
from guardia.shield.framing import MAX_MESSAGE_BYTES, FrameStatus, FrameWriter, read_frame
from guardia.shield.messages import (
    INVALID_REQUEST,
    SHIELD_BLOCKED,
    Direction,
    Message,
    MessageError,
    MessageKind,
    RequestId,
    error_response,
    parse_message,
)
from guardia.shield.session import Admission, Pending, Session

Report = Callable[[str], None]


class Verdict(enum.Enum):
    FORWARD = "forward"
    REJECT = "reject"
    DROP = "drop"
    DEFER = "defer"


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    replacement: Message | None = None
    reason: str = ""
    explanation: str = ""
    resolve: Callable[[], Decision] | None = None


FORWARD = Decision(Verdict.FORWARD)
INTERNAL_FAILURE = Decision(Verdict.REJECT, reason="internal")
MAX_DEFERRED = 8


class Inspector(Protocol):
    def inspect(
        self, direction: Direction, message: Message, pending: Pending | None
    ) -> Decision: ...


class Passthrough:
    def inspect(self, direction: Direction, message: Message, pending: Pending | None) -> Decision:
        return FORWARD


class Outcome(enum.StrEnum):
    FORWARDED = "forwarded"
    REJECTED = "rejected"
    DROPPED = "dropped"
    MALFORMED = "malformed"
    OVERSIZED = "oversized"
    UNSOLICITED = "unsolicited"


class Proxy:
    def __init__(
        self,
        *,
        to_client: FrameWriter,
        to_server: FrameWriter,
        inspector: Inspector,
        report: Report,
        t: Translator,
        limit: int = MAX_MESSAGE_BYTES,
    ) -> None:
        self._writers = {Direction.TO_CLIENT: to_client, Direction.TO_SERVER: to_server}
        self._inspector = inspector
        self._report_line = report
        self._t = t
        self._limit = limit
        self._stats_lock = threading.Lock()
        self.session = Session()
        self.stats: Counter[tuple[Direction, Outcome]] = Counter()
        self._deferred = 0

    def total(self, *outcomes: Outcome) -> int:
        with self._stats_lock:
            return sum(count for (_, outcome), count in self.stats.items() if outcome in outcomes)

    def _count(self, direction: Direction, outcome: Outcome) -> None:
        with self._stats_lock:
            self.stats[(direction, outcome)] += 1

    def _report(self, key: str, direction: Direction, **values: object) -> None:
        self._report_line(self._t(key, side=self._t(f"shield.{direction.value}"), **values))

    def _error(
        self, request_id: RequestId | None, code: int, key: str, explanation: str = ""
    ) -> bytes:
        text = self._t(key) + (" " + explanation if explanation else "")
        return error_response(request_id, code, text).encode()

    def pump(self, direction: Direction, source: IO[bytes]) -> None:
        while True:
            frame = read_frame(source, self._limit)
            if frame.status is FrameStatus.END:
                return
            if frame.status is FrameStatus.OVERSIZED:
                self._count(direction, Outcome.OVERSIZED)
                self._report("shield.oversized", direction, size=frame.size)
                continue
            if not self._handle(direction, frame.data):
                return

    def _handle(self, direction: Direction, data: bytes) -> bool:
        try:
            message = parse_message(data)
        except MessageError as exc:
            self._count(direction, Outcome.MALFORMED)
            self._report("shield.malformed", direction, problem=exc.problem.value)
            if exc.request and exc.request_id is not None:
                self._writers[direction.opposite].write(
                    self._error(exc.request_id, INVALID_REQUEST, "shield.invalid")
                )
            return True
        pending = self._admit(direction, message)
        if pending is False:
            return True
        request = pending if isinstance(pending, Pending) else None
        self.session.observe(message, request)
        return self._apply(direction, message, self._decide(direction, message, request))

    def _admit(self, direction: Direction, message: Message) -> Pending | bool:
        if message.kind is MessageKind.RESPONSE:
            pending = self.session.complete(direction, message)
            if pending is None:
                self._count(direction, Outcome.UNSOLICITED)
                self._report("shield.unsolicited", direction)
                return False
            return pending
        if message.kind is MessageKind.NOTIFICATION:
            self.session.cancel(direction, message)
            return True
        admission = self.session.begin(direction, message)
        if admission is Admission.ACCEPTED:
            return True
        key = "shield.duplicate" if admission is Admission.DUPLICATE else "shield.too_many"
        self._count(direction, Outcome.REJECTED)
        self._report(key, direction)
        self._writers[direction.opposite].write(self._error(message.id, INVALID_REQUEST, key))
        return False

    def _decide(self, direction: Direction, message: Message, pending: Pending | None) -> Decision:
        try:
            decision = self._inspector.inspect(direction, message, pending)
        except Exception:
            self._report("shield.inspector_failed", direction)
            return INTERNAL_FAILURE
        if not isinstance(decision, Decision):
            self._report("shield.inspector_failed", direction)
            return INTERNAL_FAILURE
        return decision

    def _reserve(self) -> bool:
        with self._stats_lock:
            if self._deferred >= MAX_DEFERRED:
                return False
            self._deferred += 1
            return True

    def _release(self) -> None:
        with self._stats_lock:
            self._deferred -= 1

    def _defer(self, direction: Direction, message: Message, decision: Decision) -> bool:
        if decision.resolve is None or not self._reserve():
            self._report("shield.too_many_waiting", direction)
            return self._apply(direction, message, INTERNAL_FAILURE)
        threading.Thread(
            target=self._settle,
            args=(direction, message, decision.resolve),
            name="guardia-shield-confirm",
            daemon=True,
        ).start()
        return True

    def _settle(
        self, direction: Direction, message: Message, resolve: Callable[[], Decision]
    ) -> None:
        try:
            final = resolve()
        except Exception:
            self._report("shield.inspector_failed", direction)
            final = INTERNAL_FAILURE
        if not isinstance(final, Decision) or final.verdict is Verdict.DEFER:
            final = INTERNAL_FAILURE
        try:
            self._apply(direction, message, final)
        finally:
            self._release()

    def _apply(self, direction: Direction, message: Message, decision: Decision) -> bool:
        if decision.verdict is Verdict.DEFER:
            return self._defer(direction, message, decision)
        target = self._writers[direction]
        if decision.verdict is Verdict.FORWARD:
            self._count(direction, Outcome.FORWARDED)
            return target.write((decision.replacement or message).encode())
        rejected = decision.verdict is Verdict.REJECT
        self._count(direction, Outcome.REJECTED if rejected else Outcome.DROPPED)
        if message.kind is MessageKind.REQUEST and message.id is not None:
            self.session.forget(direction, message.id)
            if rejected:
                self._writers[direction.opposite].write(
                    self._error(message.id, SHIELD_BLOCKED, "shield.blocked", decision.explanation)
                )
        elif message.kind is MessageKind.RESPONSE and rejected:
            return target.write(
                self._error(message.id, SHIELD_BLOCKED, "shield.blocked", decision.explanation)
            )
        return True
