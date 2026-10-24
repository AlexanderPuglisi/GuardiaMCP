from __future__ import annotations

import contextlib
import os
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guardia import __version__
from guardia.model import (
    TOOL_NAME,
    Finding,
    Location,
    Scope,
    ServerEntry,
    ToolCollection,
    canonical_json,
    frozen_mapping,
    sha256_hex,
)
from guardia.safeio import SafeReadError, parse_json, read_text
from guardia.scanner.rules import RULES

BASELINE_FORMAT = 1
BASELINE_FILE = "baseline.json"
MAX_BASELINE_BYTES = 32 * 1024 * 1024


class BaselineStatus:
    DISABLED = "disabled"
    CREATED = "created"
    COMPARED = "compared"
    ACCEPTED = "accepted"
    DAMAGED = "damaged"
    ERROR = "error"


@dataclass(slots=True)
class BaselineResult:
    path: Path | None
    status: str
    written: bool = False
    findings: dict[str, list[Finding]] = field(default_factory=lambda: defaultdict(list))
    file_findings: list[Finding] = field(default_factory=list)


def snapshot(
    servers: Sequence[ServerEntry], collections: Mapping[str, ToolCollection]
) -> dict[str, Any]:
    entries: dict[str, Any] = {}
    for server in servers:
        collection = collections.get(server.key)
        tools = None
        if collection is not None and collection.analyzed:
            tools = {tool.identity: tool.fingerprint for tool in collection.tools}
        entries[server.key] = {
            "name": server.name,
            "kind": server.source.scope.value if server.source.scope is Scope.SKILL else "server",
            "config": server.fingerprint,
            "tools": tools,
        }
    return entries


def _checksum(servers: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(servers))


def _document(servers: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "format": BASELINE_FORMAT,
        "tool": TOOL_NAME,
        "version": __version__,
        "updated_at": datetime.now(UTC).isoformat(),
        "checksum": _checksum(servers),
        "servers": servers,
    }


def _valid_entry(entry: Any) -> bool:
    if not isinstance(entry, dict) or not isinstance(entry.get("config"), str):
        return False
    tools = entry.get("tools")
    if tools is None:
        return True
    return isinstance(tools, dict) and all(isinstance(v, str) for v in tools.values())


def load_baseline(path: Path) -> dict[str, Any] | None:
    try:
        document = parse_json(read_text(path, MAX_BASELINE_BYTES)).value
    except SafeReadError as exc:
        if exc.code.value == "missing":
            return None
        raise
    servers = document.get("servers") if isinstance(document, dict) else None
    if (
        not isinstance(document, dict)
        or document.get("format") != BASELINE_FORMAT
        or not isinstance(servers, dict)
        or document.get("checksum") != _checksum(servers)
        or not all(_valid_entry(entry) for entry in servers.values())
    ):
        raise ValueError("invalid baseline")
    return servers


def write_baseline(path: Path, servers: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(_document(servers))
    handle, temporary = tempfile.mkstemp(prefix=".baseline-", dir=path.parent)
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


def _finding(rule_id: str, location: Location, evidence: str, **params: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=RULES[rule_id].severity,
        location=location,
        evidence=evidence,
        params=frozen_mapping(params),
    )


def _split_identity(identity: str) -> tuple[str, str]:
    kind, _, name = identity.partition(":")
    return kind, name


def compare(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    servers: Sequence[ServerEntry],
    collections: Mapping[str, ToolCollection],
    result: BaselineResult,
) -> None:
    tracks_skills = any(entry.get("kind") == "skill" for entry in previous.values())
    for server in servers:
        old = previous.get(server.key)
        new = current[server.key]
        if old is None:
            if new.get("kind") != "skill" or tracks_skills:
                result.findings[server.key].append(
                    _finding("G03-006", server.location, server.name, server=server.name)
                )
            continue
        if old["config"] != new["config"]:
            result.findings[server.key].append(
                _finding("G03-003", server.location, server.name, server=server.name)
            )
        old_tools, new_tools = old.get("tools"), new.get("tools")
        if old_tools is None or new_tools is None:
            continue
        locations = {t.identity: t.location for t in collections[server.key].tools}
        for identity, fingerprint in new_tools.items():
            kind, name = _split_identity(identity)
            location = locations.get(identity, server.location)
            if identity not in old_tools:
                result.findings[server.key].append(
                    _finding("G03-002", location, name, server=server.name, tool=name, kind=kind)
                )
            elif old_tools[identity] != fingerprint:
                result.findings[server.key].append(
                    _finding("G03-001", location, name, server=server.name, tool=name, kind=kind)
                )
        for identity in old_tools.keys() - new_tools.keys():
            kind, name = _split_identity(identity)
            result.findings[server.key].append(
                _finding("G03-004", server.location, name, server=server.name, tool=name, kind=kind)
            )


def merge(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    merged = {key: dict(value) for key, value in previous.items()}
    for key, entry in current.items():
        old = merged.get(key)
        if old is None:
            merged[key] = dict(entry)
            continue
        if entry.get("tools") is None:
            continue
        if old.get("tools") is None:
            old["tools"] = dict(entry["tools"])
            continue
        tools = dict(old["tools"])
        for identity, fingerprint in entry["tools"].items():
            tools.setdefault(identity, fingerprint)
        old["tools"] = tools
    return merged


def run_baseline(
    directory: Path | None,
    servers: Sequence[ServerEntry],
    collections: Mapping[str, ToolCollection],
    *,
    accept: bool = False,
    write: bool = True,
) -> BaselineResult:
    if directory is None:
        return BaselineResult(path=None, status=BaselineStatus.DISABLED)
    path = directory / BASELINE_FILE
    current = snapshot(servers, collections)
    try:
        previous = load_baseline(path)
    except (SafeReadError, ValueError):
        result = BaselineResult(path=path, status=BaselineStatus.DAMAGED)
        if accept and write:
            write_baseline(path, current)
            result.status, result.written = BaselineStatus.ACCEPTED, True
        else:
            result.file_findings.append(
                _finding("G03-005", Location(path), str(path), path=str(path))
            )
        return result
    if previous is None:
        result = BaselineResult(path=path, status=BaselineStatus.CREATED)
        if write:
            write_baseline(path, current)
            result.written = True
        return result
    if accept:
        result = BaselineResult(path=path, status=BaselineStatus.ACCEPTED)
        if write:
            write_baseline(path, current)
            result.written = True
        return result
    result = BaselineResult(path=path, status=BaselineStatus.COMPARED)
    compare(previous, current, servers, collections, result)
    merged = merge(previous, current)
    if write and merged != previous:
        write_baseline(path, merged)
        result.written = True
    return result
