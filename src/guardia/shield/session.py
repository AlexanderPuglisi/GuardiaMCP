from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field

from guardia.shield.messages import Direction, Message, MessageKind, RequestId, valid_id

MAX_PENDING = 10_000
VERSION_META = "io.modelcontextprotocol/protocolVersion"
MAX_VERSION_LENGTH = 32

PendingKey = tuple[str, str | int]


class Admission(enum.Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    FULL = "full"


@dataclass(frozen=True, slots=True)
class Pending:
    method: str
    started: float
    params_name: str = ""


def pending_key(request_id: RequestId) -> PendingKey:
    return (type(request_id).__name__, request_id)


def cancelled_request(message: Message) -> RequestId | None:
    if message.method != "notifications/cancelled":
        return None
    request_id = message.params.get("requestId")
    if valid_id(request_id) and isinstance(request_id, str | int):
        return request_id
    return None


def _version(value: object) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= MAX_VERSION_LENGTH:
        return value
    return None


@dataclass(slots=True)
class Session:
    pending: dict[Direction, dict[PendingKey, Pending]] = field(
        default_factory=lambda: {direction: {} for direction in Direction}
    )
    versions: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def begin(self, direction: Direction, message: Message) -> Admission:
        if message.kind is not MessageKind.REQUEST or message.id is None:
            return Admission.ACCEPTED
        name = message.params.get("name")
        entry = Pending(
            message.method or "", time.monotonic(), name if isinstance(name, str) else ""
        )
        with self._lock:
            table = self.pending[direction]
            key = pending_key(message.id)
            if key in table:
                return Admission.DUPLICATE
            if len(table) >= MAX_PENDING:
                return Admission.FULL
            table[key] = entry
        return Admission.ACCEPTED

    def complete(self, direction: Direction, message: Message) -> Pending | None:
        if message.id is None:
            return None
        with self._lock:
            return self.pending[direction.opposite].pop(pending_key(message.id), None)

    def forget(self, direction: Direction, request_id: RequestId) -> None:
        with self._lock:
            self.pending[direction].pop(pending_key(request_id), None)

    def cancel(self, direction: Direction, message: Message) -> None:
        request_id = cancelled_request(message)
        if request_id is not None:
            self.forget(direction, request_id)

    def observe(self, message: Message, pending: Pending | None = None) -> None:
        found: list[str | None] = []
        meta = message.params.get("_meta")
        if isinstance(meta, dict):
            found.append(_version(meta.get(VERSION_META)))
        if message.method == "initialize":
            found.append(_version(message.params.get("protocolVersion")))
        result = message.payload.get("result")
        if pending is not None and isinstance(result, dict):
            if pending.method == "initialize":
                found.append(_version(result.get("protocolVersion")))
            if pending.method == "server/discover":
                versions = result.get("supportedVersions")
                if isinstance(versions, list):
                    found.extend(_version(item) for item in versions[:20])
        with self._lock:
            self.versions.update(version for version in found if version)

    def in_flight(self) -> int:
        with self._lock:
            return sum(len(table) for table in self.pending.values())
