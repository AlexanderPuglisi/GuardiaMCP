from __future__ import annotations

import enum
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardia.filelock import exclusive
from guardia.ledger import Ledger, write_atomic
from guardia.model import Inventory, Scope, ServerEntry, sha256_hex
from guardia.safeio import SafeReadError, decode_text, parse_json, read_bytes
from guardia.shield.wrapping import unwrap, wrap

ACTIVATIONS_FILE = "scudo-attivazioni.json"
LOCK_FILE = "scudo-attivazioni.lock"
BACKUP_DIR = "backup"
MAX_CONFIG_BYTES = 32 * 1024 * 1024
UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class Support(enum.StrEnum):
    AUTO = "auto"
    PROTECTED = "protected"
    MANUAL_COMMENTS = "manual_comments"
    MANUAL_TOML = "manual_toml"
    EXTENSION = "extension"
    PLUGIN = "plugin"
    MANAGED = "managed"
    REMOTE = "remote"
    UNREADABLE = "unreadable"


class Outcome(enum.StrEnum):
    DONE = "done"
    CHANGED = "changed"
    MISSING = "missing"
    NOT_RECORDED = "not_recorded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Candidate:
    server: ServerEntry
    support: Support


@dataclass(frozen=True, slots=True)
class Change:
    server: str
    file: Path
    outcome: Outcome
    detail: str = ""


@dataclass(slots=True)
class Report:
    changes: list[Change] = field(default_factory=list)
    backups: list[Path] = field(default_factory=list)


def _decode_pointer(pointer: str) -> list[str]:
    if not pointer:
        return []
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]


def _locate(document: Any, pointer: str) -> tuple[dict[str, Any], str] | None:
    parts = _decode_pointer(pointer)
    if not parts:
        return None
    node = document
    for part in parts[:-1]:
        if not isinstance(node, dict) or not isinstance(node.get(part), dict):
            return None
        node = node[part]
    if not isinstance(node, dict) or not isinstance(node.get(parts[-1]), dict):
        return None
    return node, parts[-1]


def _strict_document(path: Path) -> tuple[bytes, Any] | Support:
    if path.suffix.lower() == ".toml":
        return Support.MANUAL_TOML
    try:
        data = read_bytes(path, MAX_CONFIG_BYTES)
        parsed = parse_json(decode_text(data))
    except SafeReadError:
        try:
            parse_json(decode_text(read_bytes(path, MAX_CONFIG_BYTES)), jsonc=True)
        except SafeReadError:
            return Support.UNREADABLE
        return Support.MANUAL_COMMENTS
    if parsed.duplicate_keys or not isinstance(parsed.value, dict):
        return Support.UNREADABLE
    return data, parsed.value


SCOPE_SUPPORT = {
    Scope.EXTENSION: Support.EXTENSION,
    Scope.PLUGIN: Support.PLUGIN,
    Scope.MANAGED: Support.MANAGED,
}


def support(server: ServerEntry) -> Support:
    if server.shielded:
        return Support.PROTECTED
    fixed = SCOPE_SUPPORT.get(server.source.scope)
    if fixed is not None:
        return fixed
    if not server.command or server.url:
        return Support.REMOTE
    document = _strict_document(server.source.path)
    return document if isinstance(document, Support) else Support.AUTO


def candidates(inventory: Inventory) -> list[Candidate]:
    return [Candidate(server, support(server)) for server in inventory.servers]


def _backup_name(path: Path) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}-{UNSAFE_NAME.sub('_', path.parent.name)}-{UNSAFE_NAME.sub('_', path.name)}"


def _serialize(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


class ActivationStore:
    def __init__(self, directory: Path, ledger: Ledger | None = None) -> None:
        self.directory = directory
        self.path = directory / ACTIVATIONS_FILE
        self._ledger = ledger

    def _records(self) -> list[dict[str, Any]]:
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            return []
        records = document.get("activations") if isinstance(document, dict) else None
        return [r for r in records if isinstance(r, dict)] if isinstance(records, list) else []

    def _save(self, records: list[dict[str, Any]]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        write_atomic(self.path, _serialize({"version": 1, "activations": records}))

    def records(self) -> list[dict[str, Any]]:
        with exclusive(self.directory / LOCK_FILE):
            return self._records()

    def _backup(self, path: Path, data: bytes) -> Path:
        folder = self.directory / BACKUP_DIR
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / _backup_name(path)
        write_atomic(target, data)
        return target

    def _rewrite(self, path: Path, data: bytes, document: Any, report: Report) -> bool:
        current = read_bytes(path, MAX_CONFIG_BYTES)
        if sha256_hex(current) != sha256_hex(data):
            return False
        report.backups.append(self._backup(path, data))
        write_atomic(path, _serialize(document))
        return True

    def enable(self, servers: Sequence[ServerEntry], starter: Sequence[str]) -> Report:
        report = Report()
        grouped: dict[Path, list[ServerEntry]] = defaultdict(list)
        for server in servers:
            grouped[server.source.path].append(server)
        with exclusive(self.directory / LOCK_FILE):
            records = self._records()
            for path, group in grouped.items():
                self._enable_file(path, group, starter, records, report)
            self._save(records)
        return report

    def _enable_file(
        self,
        path: Path,
        group: list[ServerEntry],
        starter: Sequence[str],
        records: list[dict[str, Any]],
        report: Report,
    ) -> None:
        loaded = _strict_document(path)
        if isinstance(loaded, Support):
            report.changes += [Change(s.name, path, Outcome.FAILED, loaded.value) for s in group]
            return
        data, document = loaded
        pending: list[tuple[ServerEntry, dict[str, Any], dict[str, Any]]] = []
        for server in group:
            found = _locate(document, server.pointer)
            if found is None:
                report.changes.append(Change(server.name, path, Outcome.MISSING))
                continue
            parent, key = found
            original = parent[key]
            if unwrap(original.get("command"), original.get("args") or []) is not None:
                report.changes.append(Change(server.name, path, Outcome.CHANGED, "already"))
                continue
            if original.get("command") != server.command:
                report.changes.append(Change(server.name, path, Outcome.CHANGED))
                continue
            command, args = wrap(starter, server.name, server.command or "", list(server.args))
            wrapped = {**original, "command": command, "args": args}
            parent[key] = wrapped
            pending.append((server, original, wrapped))
        if not pending:
            return
        if not self._rewrite(path, data, document, report):
            report.changes += [Change(s.name, path, Outcome.CHANGED, "file") for s, _, _ in pending]
            return
        now = datetime.now(UTC).isoformat(timespec="seconds")
        for server, original, wrapped in pending:
            records.append(
                {
                    "file": str(path),
                    "pointer": server.pointer,
                    "server": server.name,
                    "client": server.source.client.value,
                    "original": original,
                    "wrapped": wrapped,
                    "backup": str(report.backups[-1]),
                    "at": now,
                }
            )
            report.changes.append(Change(server.name, path, Outcome.DONE))
        if self._ledger is not None:
            self._ledger.append(
                "shield_enabled",
                {"file": str(path), "servers": sorted(s.name for s, _, _ in pending)},
            )

    def disable(self, names: Iterable[str] | None = None) -> Report:
        wanted = set(names) if names is not None else None
        report = Report()
        with exclusive(self.directory / LOCK_FILE):
            records = self._records()
            chosen = [r for r in records if wanted is None or r.get("server") in wanted]
            if wanted:
                known = {r.get("server") for r in records}
                report.changes += [
                    Change(name, Path(), Outcome.NOT_RECORDED) for name in sorted(wanted - known)
                ]
            grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for record in chosen:
                grouped[str(record.get("file", ""))].append(record)
            for file, group in grouped.items():
                done = self._disable_file(Path(file), group, report)
                records = [r for r in records if r not in done]
            self._save(records)
        return report

    def _disable_file(
        self, path: Path, group: list[dict[str, Any]], report: Report
    ) -> list[dict[str, Any]]:
        loaded = _strict_document(path)
        if isinstance(loaded, Support):
            report.changes += [
                Change(str(r.get("server")), path, Outcome.FAILED, loaded.value) for r in group
            ]
            return []
        data, document = loaded
        restored: list[dict[str, Any]] = []
        for record in group:
            found = _locate(document, str(record.get("pointer", "")))
            if found is None:
                report.changes.append(Change(str(record.get("server")), path, Outcome.MISSING))
                continue
            parent, key = found
            if parent[key] != record.get("wrapped"):
                report.changes.append(Change(str(record.get("server")), path, Outcome.CHANGED))
                continue
            parent[key] = record.get("original")
            restored.append(record)
        if not restored:
            return []
        if not self._rewrite(path, data, document, report):
            report.changes += [
                Change(str(r.get("server")), path, Outcome.CHANGED, "file") for r in restored
            ]
            return []
        report.changes += [Change(str(r.get("server")), path, Outcome.DONE) for r in restored]
        if self._ledger is not None:
            self._ledger.append(
                "shield_disabled",
                {"file": str(path), "servers": sorted(str(r.get("server")) for r in restored)},
            )
        return restored


def manual_snippet(server: ServerEntry, starter: Sequence[str]) -> str:
    command, args = wrap(starter, server.name, server.command or "", list(server.args))
    return json.dumps({"command": command, "args": args}, ensure_ascii=False, indent=2)
