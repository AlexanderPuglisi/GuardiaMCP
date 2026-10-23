from __future__ import annotations

import enum
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from guardia.ledger import KEY_FILE, Ledger, write_atomic
from guardia.model import canonical_json, sha256_hex
from guardia.safeio import SafeReadError, decode_text, read_bytes
from guardia.secure_store import KeyStore, KeyStoreError, Protector
from guardia.shield.rules import ParseResult, RuleSet, parse_rules

RULES_FILE = "regole.toml"
SIGNATURE_FILE = "regole.firma"
APPROVED_FILE = "regole.approvate.toml"
MAX_RULES_BYTES = 1024 * 1024
RELOAD_SECONDS = 1.0


class PolicyState(enum.StrEnum):
    NONE = "none"
    ACTIVE = "active"
    LOCKED = "locked"


class LockReason(enum.StrEnum):
    UNAPPROVED = "unapproved"
    MODIFIED = "modified"
    MISSING = "missing"
    INVALID = "invalid"
    KEY = "key"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class Policy:
    state: PolicyState
    ruleset: RuleSet | None = None
    reason: LockReason | None = None


class ApprovalError(Exception):
    pass


class RulesChangedError(ApprovalError):
    pass


def rules_mac(key: bytes, digest: str) -> str:
    return hmac.new(key, f"rules:{digest}".encode(), hashlib.sha256).hexdigest()


def rules_path(directory: Path) -> Path:
    return directory / RULES_FILE


def read_rules_text(path: Path) -> str:
    return decode_text(read_bytes(path, MAX_RULES_BYTES))


def _signature(directory: Path) -> dict[str, object] | None:
    try:
        value = json.loads((directory / SIGNATURE_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


class _LockedError(Exception):
    def __init__(self, reason: LockReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


def _read_signed(directory: Path, protector: Protector | None) -> bytes | None:
    path = rules_path(directory)
    signature = _signature(directory)
    if not path.exists():
        if signature is None:
            return None
        raise _LockedError(LockReason.MISSING)
    try:
        data = read_bytes(path, MAX_RULES_BYTES)
    except SafeReadError as exc:
        raise _LockedError(LockReason.UNREADABLE) from exc
    if signature is None:
        raise _LockedError(LockReason.UNAPPROVED)
    try:
        key = KeyStore(directory / KEY_FILE, protector).load()
    except KeyStoreError:
        key = None
    if key is None:
        raise _LockedError(LockReason.KEY)
    digest = sha256_hex(data)
    mac = signature.get("mac")
    if (
        signature.get("sha256") != digest
        or not isinstance(mac, str)
        or not hmac.compare_digest(rules_mac(key, digest), mac)
    ):
        raise _LockedError(LockReason.MODIFIED)
    return data


def load_policy(directory: Path, home: str, protector: Protector | None = None) -> Policy:
    try:
        data = _read_signed(directory, protector)
    except _LockedError as exc:
        return Policy(PolicyState.LOCKED, reason=exc.reason)
    if data is None:
        return Policy(PolicyState.NONE)
    try:
        result = parse_rules(decode_text(data), home)
    except SafeReadError:
        return Policy(PolicyState.LOCKED, reason=LockReason.UNREADABLE)
    if result.ruleset is None:
        return Policy(PolicyState.LOCKED, reason=LockReason.INVALID)
    return Policy(PolicyState.ACTIVE, result.ruleset)


def approved_text(directory: Path) -> str | None:
    try:
        return (directory / APPROVED_FILE).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def approve_rules(
    directory: Path,
    home: str,
    protector: Protector | None = None,
    *,
    expected: bytes | None = None,
) -> tuple[ParseResult, str]:
    path = rules_path(directory)
    data = read_bytes(path, MAX_RULES_BYTES)
    if expected is not None and data != expected:
        raise RulesChangedError(str(path))
    text = decode_text(data)
    result = parse_rules(text, home)
    if result.ruleset is None:
        return result, text
    digest = sha256_hex(data)
    try:
        key, _ = KeyStore(directory / KEY_FILE, protector).load_or_create()
        Ledger(directory, protector).append(
            "rules_approved",
            {
                "sha256": digest,
                "rules": len(result.ruleset.rules),
                "default": result.ruleset.default.value,
            },
        )
    except (OSError, KeyStoreError) as exc:
        raise ApprovalError(str(exc) or type(exc).__name__) from exc
    write_atomic(directory / APPROVED_FILE, text.encode("utf-8"))
    signature = {
        "sha256": digest,
        "mac": rules_mac(key, digest),
        "approved_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "rules": len(result.ruleset.rules),
    }
    write_atomic(directory / SIGNATURE_FILE, canonical_json(signature))
    return result, text


def _stamp(path: Path) -> tuple[int, int] | None:
    try:
        info = path.stat()
    except OSError:
        return None
    return info.st_mtime_ns, info.st_size


class PolicyWatcher:
    def __init__(
        self,
        directory: Path,
        home: str,
        protector: Protector | None = None,
        interval: float = RELOAD_SECONDS,
    ) -> None:
        self._directory = directory
        self._home = home
        self._protector = protector
        self._interval = interval
        self._lock = threading.Lock()
        self._stamps = self._read_stamps()
        self._policy = load_policy(directory, home, protector)
        self._checked = time.monotonic()

    def _read_stamps(self) -> tuple[tuple[int, int] | None, ...]:
        return (
            _stamp(rules_path(self._directory)),
            _stamp(self._directory / SIGNATURE_FILE),
            _stamp(self._directory / KEY_FILE),
        )

    def current(self) -> Policy:
        with self._lock:
            now = time.monotonic()
            if now - self._checked >= self._interval:
                self._checked = now
                stamps = self._read_stamps()
                if stamps != self._stamps:
                    self._stamps = stamps
                    self._policy = load_policy(self._directory, self._home, self._protector)
            return self._policy
