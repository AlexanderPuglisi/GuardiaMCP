from __future__ import annotations

import contextlib
import enum
import hashlib
import hmac
import json
import os
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardia import __version__
from guardia.filelock import exclusive
from guardia.model import canonical_json, sha256_hex
from guardia.secure_store import KeyStore, KeyStoreError, Protector

LEDGER_FILE = "registro.jsonl"
HEAD_FILE = "registro.head"
KEY_FILE = "registro.key"
LOCK_FILE = "registro.lock"
GENESIS = "0" * 64
MAX_LINE_BYTES = 1024 * 1024


class LedgerProblem(enum.StrEnum):
    MALFORMED = "malformed"
    SEQUENCE = "sequence"
    CHAIN = "chain"
    HASH = "hash"
    MAC = "mac"
    HEAD_MISMATCH = "head_mismatch"
    HEAD_MISSING = "head_missing"
    KEY_MISSING = "key_missing"
    KEY_UNREADABLE = "key_unreadable"
    ANCHOR_MISMATCH = "anchor_mismatch"


TAMPERING = frozenset(
    {
        LedgerProblem.MALFORMED,
        LedgerProblem.SEQUENCE,
        LedgerProblem.CHAIN,
        LedgerProblem.HASH,
        LedgerProblem.MAC,
        LedgerProblem.HEAD_MISMATCH,
        LedgerProblem.HEAD_MISSING,
        LedgerProblem.ANCHOR_MISMATCH,
    }
)


@dataclass(frozen=True, slots=True)
class Issue:
    problem: LedgerProblem
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"problem": self.problem.value, "line": self.line}


@dataclass(slots=True)
class Verification:
    records: int = 0
    head_seq: int = 0
    head_hash: str = GENESIS
    issues: list[Issue] = field(default_factory=list)

    @property
    def intact(self) -> bool:
        return not self.issues

    @property
    def tampered(self) -> bool:
        return any(issue.problem in TAMPERING for issue in self.issues)

    @property
    def anchor(self) -> str:
        return f"{self.head_seq}:{self.head_hash}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": self.records,
            "intact": self.intact,
            "tampered": self.tampered,
            "anchor": self.anchor,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def record_hash(record: Mapping[str, Any]) -> str:
    body = {key: record[key] for key in ("seq", "time", "event", "data", "prev")}
    return sha256_hex(canonical_json(body))


def record_mac(key: bytes, digest: str) -> str:
    return hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()


def head_mac(key: bytes, seq: int, digest: str) -> str:
    return record_mac(key, f"head:{seq}:{digest}")


def write_atomic(path: Path, payload: bytes) -> None:
    handle, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(path)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise


class Ledger:
    def __init__(self, directory: Path, protector: Protector | None = None) -> None:
        self.directory = directory
        self.path = directory / LEDGER_FILE
        self.head_path = directory / HEAD_FILE
        self.keys = KeyStore(directory / KEY_FILE, protector)

    def _key(self, create: bool) -> tuple[bytes | None, Issue | None]:
        try:
            if create:
                return self.keys.load_or_create()[0], None
            key = self.keys.load()
        except KeyStoreError:
            return None, Issue(LedgerProblem.KEY_UNREADABLE)
        if key is None:
            return None, Issue(LedgerProblem.KEY_MISSING)
        return key, None

    def lines(self) -> Iterator[tuple[int, str]]:
        try:
            with self.path.open("rb") as stream:
                for number, raw in enumerate(stream, start=1):
                    line = raw.decode("utf-8", errors="replace")
                    if line.strip():
                        yield number, line
        except FileNotFoundError:
            return

    def records(self) -> Iterator[dict[str, Any]]:
        for _, line in self.lines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record

    def verify(self, anchor: str | None = None) -> Verification:
        with exclusive(self.directory / LOCK_FILE):
            return self._verify(anchor)

    def _verify(self, anchor: str | None) -> Verification:
        result = Verification()
        anchors: dict[int, str] = {0: GENESIS}
        if not self.path.exists() and not self.head_path.exists():
            self._check_anchor(result, anchor, anchors)
            return result
        key, key_issue = self._key(create=False)
        if key_issue is not None:
            result.issues.append(key_issue)
        previous = GENESIS
        expected_seq = 1
        for number, line in self.lines():
            try:
                record = json.loads(line) if len(line) <= MAX_LINE_BYTES else None
            except ValueError:
                record = None
            if (
                not isinstance(record, dict)
                or not {"seq", "time", "event", "data", "prev", "hash", "mac"} <= record.keys()
            ):
                result.issues.append(Issue(LedgerProblem.MALFORMED, number))
                continue
            if record["seq"] != expected_seq:
                result.issues.append(Issue(LedgerProblem.SEQUENCE, number))
            if record["prev"] != previous:
                result.issues.append(Issue(LedgerProblem.CHAIN, number))
            digest = record_hash(record)
            if digest != record["hash"]:
                result.issues.append(Issue(LedgerProblem.HASH, number))
            if key is not None and not hmac.compare_digest(
                record_mac(key, str(record["hash"])), str(record["mac"])
            ):
                result.issues.append(Issue(LedgerProblem.MAC, number))
            previous = str(record["hash"])
            expected_seq = (
                int(record["seq"]) + 1 if isinstance(record["seq"], int) else expected_seq + 1
            )
            result.records += 1
            result.head_seq = (
                int(record["seq"]) if isinstance(record["seq"], int) else result.head_seq
            )
            result.head_hash = previous
            anchors[result.head_seq] = previous
        self._check_head(result, key)
        self._check_anchor(result, anchor, anchors)
        return result

    def _check_anchor(
        self, result: Verification, anchor: str | None, anchors: dict[int, str]
    ) -> None:
        if anchor is None:
            return
        seq_text, _, digest = anchor.partition(":")
        if not seq_text.isdigit() or anchors.get(int(seq_text)) != digest:
            result.issues.append(Issue(LedgerProblem.ANCHOR_MISMATCH))

    def _check_head(self, result: Verification, key: bytes | None) -> None:
        try:
            head = json.loads(self.head_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if result.records:
                result.issues.append(Issue(LedgerProblem.HEAD_MISSING))
            return
        except (OSError, ValueError):
            result.issues.append(Issue(LedgerProblem.HEAD_MISMATCH))
            return
        if not isinstance(head, dict):
            result.issues.append(Issue(LedgerProblem.HEAD_MISMATCH))
            return
        same = head.get("seq") == result.head_seq and head.get("hash") == result.head_hash
        signed = key is None or hmac.compare_digest(
            head_mac(key, result.head_seq, result.head_hash), str(head.get("mac", ""))
        )
        if not same or not signed:
            result.issues.append(Issue(LedgerProblem.HEAD_MISMATCH))

    def _fast_last(self, key: bytes) -> tuple[int, str] | None:
        try:
            head = json.loads(self.head_path.read_text(encoding="utf-8"))
            size = self.path.stat().st_size
        except (OSError, ValueError):
            return None
        if not isinstance(head, dict):
            return None
        seq, digest, mac = head.get("seq"), head.get("hash"), head.get("mac")
        if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(digest, str):
            return None
        if head.get("size") != size or not isinstance(mac, str):
            return None
        if not hmac.compare_digest(head_mac(key, seq, digest), mac):
            return None
        return seq, digest

    def _last(self) -> tuple[int, str]:
        seq, digest = 0, GENESIS
        for record in self.records():
            if isinstance(record.get("seq"), int) and isinstance(record.get("hash"), str):
                seq, digest = record["seq"], record["hash"]
        return seq, digest

    def append(self, event: str, data: Mapping[str, Any]) -> dict[str, Any]:
        with exclusive(self.directory / LOCK_FILE):
            return self._append(event, data)

    def _append(self, event: str, data: Mapping[str, Any]) -> dict[str, Any]:
        key, _ = self._key(create=True)
        if key is None:
            raise KeyStoreError("ledger key unavailable")
        seq, previous = self._fast_last(key) or self._last()
        record: dict[str, Any] = {
            "seq": seq + 1,
            "time": datetime.now(UTC).isoformat(),
            "event": event,
            "data": dict(data),
            "prev": previous,
        }
        record["hash"] = record_hash(record)
        record["mac"] = record_mac(key, record["hash"])
        line = canonical_json(record) + b"\n"
        with self.path.open("ab") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        head = {
            "seq": record["seq"],
            "hash": record["hash"],
            "mac": head_mac(key, record["seq"], record["hash"]),
            "size": self.path.stat().st_size,
            "tool": "guardia-mcp",
            "version": __version__,
        }
        write_atomic(self.head_path, canonical_json(head))
        return record
