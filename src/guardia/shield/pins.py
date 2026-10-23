from __future__ import annotations

import enum
import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardia.filelock import exclusive
from guardia.ledger import KEY_FILE, Ledger, write_atomic
from guardia.model import canonical_json, sha256_hex
from guardia.secure_store import KeyStore, KeyStoreError, Protector

PINS_FILE = "scudo-strumenti.json"
LOCK_FILE = "scudo-strumenti.lock"
MAX_PINS_BYTES = 8 * 1024 * 1024
MAX_LOGGED_TOOLS = 50
PINNED_EVENT = "tools_pinned"
FORGOTTEN_EVENT = "tools_forgotten"


class ToolStatus(enum.StrEnum):
    APPROVED = "approved"
    NEW = "new"
    CHANGED = "changed"


class PinError(Exception):
    pass


@dataclass(slots=True)
class Review:
    statuses: dict[str, ToolStatus] = field(default_factory=dict)
    first_use: bool = False
    unverified: bool = False
    newly_pending: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PendingTool:
    server: str
    name: str
    fingerprint: str
    reason: ToolStatus
    seen: str


def _pins_mac(key: bytes, servers: Mapping[str, Any]) -> str:
    digest = sha256_hex(canonical_json(servers))
    return hmac.new(key, f"pins:{digest}".encode(), hashlib.sha256).hexdigest()


def _valid_entry(entry: Any) -> bool:
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("approved"), dict)
        and isinstance(entry.get("pending"), dict)
        and isinstance(entry.get("flags", {}), dict)
    )


def _set_flags(entry: dict[str, Any], tools: Mapping[str, str], flags: Mapping[str, str]) -> bool:
    current = entry.setdefault("flags", {})
    before = dict(current)
    for name in tools:
        if name in flags:
            current[name] = flags[name]
        else:
            current.pop(name, None)
    return bool(current != before)


class PinStore:
    def __init__(
        self, directory: Path, protector: Protector | None = None, ledger: Ledger | None = None
    ) -> None:
        self.directory = directory
        self.path = directory / PINS_FILE
        self._keys = KeyStore(directory / KEY_FILE, protector)
        self._ledger = ledger

    def _key(self) -> bytes:
        try:
            key, _ = self._keys.load_or_create()
        except KeyStoreError as exc:
            raise PinError(str(exc)) from exc
        return key

    def _load(self, key: bytes) -> tuple[dict[str, Any], bool, bool]:
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return {}, True, False
        except OSError as exc:
            raise PinError(str(exc)) from exc
        try:
            document = json.loads(data) if len(data) <= MAX_PINS_BYTES else None
        except ValueError:
            document = None
        if not isinstance(document, dict):
            return {}, False, True
        servers = document.get("servers")
        mac = document.get("mac")
        if (
            not isinstance(servers, dict)
            or not isinstance(mac, str)
            or not all(_valid_entry(entry) for entry in servers.values())
            or not hmac.compare_digest(_pins_mac(key, servers), mac)
        ):
            return {}, False, True
        return servers, True, True

    def _save(self, key: bytes, servers: Mapping[str, Any]) -> None:
        document = {"version": 1, "servers": servers, "mac": _pins_mac(key, servers)}
        self.directory.mkdir(parents=True, exist_ok=True)
        write_atomic(self.path, canonical_json(document))

    def _record(self, event: str, data: Mapping[str, object]) -> None:
        if self._ledger is not None:
            self._ledger.append(event, data)

    def _previously_pinned(self, server: str) -> bool:
        if self._ledger is None:
            return False
        last = None
        for record in self._ledger.records():
            event = record.get("event")
            data = record.get("data")
            if (
                event in (PINNED_EVENT, FORGOTTEN_EVENT)
                and isinstance(data, dict)
                and data.get("server") == server
            ):
                last = event
        return last == PINNED_EVENT

    def review(
        self,
        server: str,
        tools: Mapping[str, str],
        *,
        continuing: bool = False,
        flags: Mapping[str, str] | None = None,
    ) -> Review:
        hidden = flags or {}
        with exclusive(self.directory / LOCK_FILE):
            key = self._key()
            servers, valid, existed = self._load(key)
            review = Review(unverified=not valid)
            entry = servers.get(server)
            vanished = (
                entry is None and valid and not continuing and self._previously_pinned(server)
            )
            review.unverified = review.unverified or vanished
            if entry is None and valid and not vanished:
                review.first_use = True
                servers[server] = {"approved": dict(tools), "pending": {}, "flags": dict(hidden)}
                self._save(key, servers)
                self._record(
                    PINNED_EVENT,
                    {
                        "server": server,
                        "tools": sorted(tools)[:MAX_LOGGED_TOOLS],
                        "count": len(tools),
                    },
                )
                review.statuses = dict.fromkeys(tools, ToolStatus.APPROVED)
                return review
            if not valid:
                servers = {}
            entry = servers.setdefault(server, {"approved": {}, "pending": {}})
            if continuing and not entry["pending"] and valid:
                entry["approved"].update(tools)
            changed = (not valid and existed) or _set_flags(entry, tools, hidden)
            now = datetime.now(UTC).isoformat(timespec="seconds")
            for name, fingerprint in tools.items():
                approved = entry["approved"].get(name)
                if approved == fingerprint:
                    review.statuses[name] = ToolStatus.APPROVED
                    if name in entry["pending"]:
                        del entry["pending"][name]
                        changed = True
                    continue
                status = ToolStatus.NEW if approved is None else ToolStatus.CHANGED
                review.statuses[name] = status
                known = entry["pending"].get(name)
                if not isinstance(known, dict) or known.get("fingerprint") != fingerprint:
                    entry["pending"][name] = {
                        "fingerprint": fingerprint,
                        "reason": status.value,
                        "seen": now,
                    }
                    review.newly_pending.append(name)
                    changed = True
            if changed or not valid:
                self._save(key, servers)
            if review.newly_pending:
                self._record(
                    "tools_pending",
                    {
                        "server": server,
                        "tools": [
                            {
                                "name": name,
                                "reason": review.statuses[name].value,
                                "fingerprint": tools[name],
                            }
                            for name in review.newly_pending[:MAX_LOGGED_TOOLS]
                        ],
                        "unverified": not valid,
                    },
                )
            return review

    def lookup(self, server: str, tool: str) -> str | None:
        with exclusive(self.directory / LOCK_FILE):
            servers, valid, _ = self._load(self._key())
        if not valid:
            return "unverified"
        entry = servers.get(server)
        if entry is None:
            return "unknown"
        item = entry["pending"].get(tool)
        if isinstance(item, dict):
            return str(item.get("reason", ToolStatus.NEW.value))
        flag = entry.get("flags", {}).get(tool)
        if isinstance(flag, str):
            return flag
        return None if tool in entry["approved"] else "unknown"

    def pending(self) -> tuple[list[PendingTool], dict[str, int], bool]:
        with exclusive(self.directory / LOCK_FILE):
            servers, valid, _ = self._load(self._key())
        waiting: list[PendingTool] = []
        approved: dict[str, int] = {}
        for server, entry in sorted(servers.items()):
            approved[server] = len(entry["approved"])
            for name, item in sorted(entry["pending"].items()):
                if isinstance(item, dict):
                    waiting.append(
                        PendingTool(
                            server,
                            name,
                            str(item.get("fingerprint", "")),
                            ToolStatus(item.get("reason", ToolStatus.NEW.value)),
                            str(item.get("seen", "")),
                        )
                    )
        return waiting, approved, valid

    def approve(self, server: str, names: Iterable[str] = ()) -> list[str]:
        wanted = set(names)
        with exclusive(self.directory / LOCK_FILE):
            key = self._key()
            servers, valid, _ = self._load(key)
            if not valid:
                raise PinError("unverified")
            entry = servers.get(server)
            if entry is None:
                return []
            chosen = [name for name in sorted(entry["pending"]) if not wanted or name in wanted]
            for name in chosen:
                item = entry["pending"].pop(name)
                entry["approved"][name] = item["fingerprint"]
            if chosen:
                self._record(
                    "tools_approved", {"server": server, "tools": chosen[:MAX_LOGGED_TOOLS]}
                )
                self._save(key, servers)
            return chosen

    def forget(self, server: str) -> bool:
        with exclusive(self.directory / LOCK_FILE):
            key = self._key()
            servers, valid, _ = self._load(key)
            if not valid:
                raise PinError("unverified")
            if server not in servers:
                return False
            self._record(FORGOTTEN_EVENT, {"server": server})
            del servers[server]
            self._save(key, servers)
            return True
