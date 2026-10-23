from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass
from typing import Any

from guardia.safeio import ReadErrorCode, SafeReadError, depth_exceeds, parse_json

MAX_DEPTH = 100
MAX_METHOD_LENGTH = 256
MAX_ID_LENGTH = 256
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
SHIELD_BLOCKED = -32010
SURROGATE_ESCAPE = re.compile(rb"\\u[dD][89a-fA-F]")

RequestId = str | int


class MessageKind(enum.StrEnum):
    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"


class Direction(enum.StrEnum):
    TO_SERVER = "to_server"
    TO_CLIENT = "to_client"

    @property
    def opposite(self) -> Direction:
        return Direction.TO_CLIENT if self is Direction.TO_SERVER else Direction.TO_SERVER


class Problem(enum.StrEnum):
    NOT_UTF8 = "not_utf8"
    NOT_JSON = "not_json"
    DUPLICATE_KEYS = "duplicate_keys"
    TOO_DEEP = "too_deep"
    NOT_OBJECT = "not_object"
    BATCH = "batch"
    BAD_VERSION = "bad_version"
    BAD_ID = "bad_id"
    BAD_METHOD = "bad_method"
    BAD_PARAMS = "bad_params"
    BAD_RESPONSE = "bad_response"


class MessageError(Exception):
    def __init__(
        self, problem: Problem, request_id: RequestId | None = None, *, request: bool = False
    ) -> None:
        super().__init__(problem.value)
        self.problem = problem
        self.request_id = request_id
        self.request = request


@dataclass(frozen=True, slots=True)
class Message:
    kind: MessageKind
    payload: dict[str, Any]
    id: RequestId | None = None
    method: str | None = None

    @property
    def params(self) -> dict[str, Any]:
        value = self.payload.get("params")
        return value if isinstance(value, dict) else {}

    def encode(self) -> bytes:
        return json.dumps(
            self.payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")


def valid_id(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and len(value) <= MAX_ID_LENGTH


def _decode(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessageError(Problem.NOT_UTF8) from exc
    try:
        parsed = parse_json(text)
    except SafeReadError as exc:
        problem = Problem.TOO_DEEP if exc.code is ReadErrorCode.TOO_DEEP else Problem.NOT_JSON
        raise MessageError(problem) from exc
    if parsed.duplicate_keys:
        raise MessageError(Problem.DUPLICATE_KEYS)
    value = parsed.value
    if isinstance(value, list):
        raise MessageError(Problem.BATCH)
    if not isinstance(value, dict):
        raise MessageError(Problem.NOT_OBJECT)
    if depth_exceeds(value, MAX_DEPTH):
        raise MessageError(Problem.TOO_DEEP)
    return value


def _request(payload: dict[str, Any], request_id: RequestId | None) -> Message:
    method = payload["method"]
    if not isinstance(method, str) or not method or len(method) > MAX_METHOD_LENGTH:
        raise MessageError(Problem.BAD_METHOD, request_id, request=True)
    if "params" in payload and not isinstance(payload["params"], dict):
        raise MessageError(Problem.BAD_PARAMS, request_id, request=True)
    if "result" in payload or "error" in payload:
        raise MessageError(Problem.BAD_METHOD, request_id, request=True)
    if "id" not in payload:
        return Message(MessageKind.NOTIFICATION, payload, None, method)
    if request_id is None:
        raise MessageError(Problem.BAD_ID)
    return Message(MessageKind.REQUEST, payload, request_id, method)


def _response(payload: dict[str, Any], request_id: RequestId | None) -> Message:
    if "id" not in payload:
        raise MessageError(Problem.BAD_RESPONSE)
    has_result = "result" in payload
    has_error = "error" in payload
    if has_result == has_error:
        raise MessageError(Problem.BAD_RESPONSE, request_id)
    if has_result and request_id is None:
        raise MessageError(Problem.BAD_ID)
    if has_error:
        error = payload["error"]
        if (
            not isinstance(error, dict)
            or not isinstance(error.get("code"), int)
            or isinstance(error.get("code"), bool)
            or not isinstance(error.get("message"), str)
        ):
            raise MessageError(Problem.BAD_RESPONSE, request_id)
    return Message(MessageKind.RESPONSE, payload, request_id)


def _encodable(message: Message) -> Message:
    try:
        message.encode()
    except UnicodeEncodeError as exc:
        request = message.kind is MessageKind.REQUEST
        raise MessageError(Problem.NOT_UTF8, message.id, request=request) from exc
    return message


def parse_message(data: bytes) -> Message:
    payload = _decode(data)
    raw_id = payload.get("id")
    if raw_id is not None and not valid_id(raw_id):
        raise MessageError(Problem.BAD_ID)
    request_id: RequestId | None = raw_id
    if payload.get("jsonrpc") != "2.0":
        raise MessageError(Problem.BAD_VERSION, request_id, request="method" in payload)
    message = (
        _request(payload, request_id) if "method" in payload else _response(payload, request_id)
    )
    return _encodable(message) if SURROGATE_ESCAPE.search(data) else message


def error_response(request_id: RequestId | None, code: int, text: str) -> Message:
    return Message(
        MessageKind.RESPONSE,
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": text}},
        request_id,
    )
