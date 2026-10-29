from __future__ import annotations

import contextlib
import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardia.filelock import exclusive
from guardia.model import canonical_json
from guardia.secure_store import KeyStoreError, Protector, default_protector

CANARY_FILE = "canaries.json"
LOCK_FILE = "canaries.lock"
CANARY_PREFIX = "gmcp-canary-"
TOKEN_BYTES = 16
ID_BYTES = 4
MAX_NOTE = 200
MAX_CANARIES = 256
MAX_SCAN_NODES = 1_000_000


class CanaryError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Canary:
    id: str
    token: str
    created: str
    note: str
    decoy: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "token": self.token,
            "created": self.created,
            "note": self.note,
            "decoy": self.decoy,
        }


def new_token() -> str:
    return CANARY_PREFIX + secrets.token_hex(TOKEN_BYTES)


def new_id() -> str:
    return secrets.token_hex(ID_BYTES)


def decoy_text(token: str) -> str:
    return (
        "# Private credentials. Do not copy, do not share.\n"
        f"API_KEY={token}\n"
        f"AWS_SECRET_ACCESS_KEY={token}\n"
        f"DATABASE_PASSWORD={token}\n"
    )


def _parse(record: Any) -> Canary | None:
    if not isinstance(record, dict):
        return None
    token = record.get("token")
    identifier = record.get("id")
    if not isinstance(token, str) or not isinstance(identifier, str):
        return None
    created = record.get("created")
    note = record.get("note")
    decoy = record.get("decoy")
    return Canary(
        id=identifier,
        token=token,
        created=created if isinstance(created, str) else "",
        note=note if isinstance(note, str) else "",
        decoy=decoy if isinstance(decoy, str) else "",
    )


class CanaryStore:
    def __init__(self, directory: Path, protector: Protector | None = None) -> None:
        self.directory = directory
        self.path = directory / CANARY_FILE
        self.protector = protector or default_protector()

    def _read(self) -> list[Canary]:
        try:
            payload = self.path.read_bytes()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise CanaryError(exc.strerror or type(exc).__name__) from exc
        if not payload.startswith(self.protector.magic):
            raise CanaryError("unknown canary format")
        try:
            raw = json.loads(self.protector.unprotect(payload[len(self.protector.magic) :]))
        except (KeyStoreError, OSError, ValueError) as exc:
            raise CanaryError(str(exc)) from exc
        if not isinstance(raw, list):
            return []
        found: list[Canary] = []
        for item in raw:
            canary = _parse(item)
            if canary is not None:
                found.append(canary)
        return found

    def _write(self, canaries: list[Canary]) -> None:
        payload = self.protector.magic + self.protector.protect(
            canonical_json([canary.to_dict() for canary in canaries])
        )
        self.directory.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=".canary-", dir=self.directory)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            Path(temporary).replace(self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                Path(temporary).unlink()
            raise

    def all(self) -> list[Canary]:
        with exclusive(self.directory / LOCK_FILE):
            return self._read()

    def tokens(self) -> frozenset[str]:
        return frozenset(canary.token for canary in self.all())

    def add(self, note: str = "", decoy: str = "") -> Canary:
        with exclusive(self.directory / LOCK_FILE):
            existing = self._read()
            if len(existing) >= MAX_CANARIES:
                raise CanaryError("too many canaries")
            taken = {canary.id for canary in existing}
            identifier = new_id()
            while identifier in taken:
                identifier = new_id()
            canary = Canary(
                id=identifier,
                token=new_token(),
                created=datetime.now(UTC).isoformat(),
                note=note[:MAX_NOTE],
                decoy=decoy,
            )
            self._write([*existing, canary])
            return canary

    def remove(self, identifier: str) -> Canary | None:
        with exclusive(self.directory / LOCK_FILE):
            existing = self._read()
            kept = [canary for canary in existing if canary.id != identifier]
            if len(kept) == len(existing):
                return None
            removed = next(canary for canary in existing if canary.id == identifier)
            self._write(kept)
            return removed


def plant(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(decoy_text(token), encoding="utf-8")


def find_canary(value: Any, tokens: frozenset[str]) -> str | None:
    if not tokens:
        return None
    stack: list[Any] = [value]
    seen = 0
    while stack and seen < MAX_SCAN_NODES:
        current = stack.pop()
        seen += 1
        if isinstance(current, str):
            for token in tokens:
                if token in current:
                    return token
        elif isinstance(current, dict):
            for key, item in current.items():
                if isinstance(key, str):
                    for token in tokens:
                        if token in key:
                            return token
                stack.append(item)
        elif isinstance(current, list):
            stack.extend(current)
    return None
