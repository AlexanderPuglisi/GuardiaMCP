from __future__ import annotations

import enum
import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from pathlib import Path
from types import MappingProxyType
from typing import Any

from guardia import __version__
from guardia.redact import redact_args, redact_url

TOOL_NAME = "guardia-mcp"


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Transport(enum.StrEnum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class Client(enum.StrEnum):
    CLAUDE_DESKTOP = "claude-desktop"
    CLAUDE_CODE = "claude-code"
    CURSOR = "cursor"
    VSCODE = "vscode"
    WINDSURF = "windsurf"
    GEMINI_CLI = "gemini-cli"
    CODEX = "codex"
    COPILOT_CLI = "copilot-cli"
    MANUAL = "manual"


class Scope(enum.StrEnum):
    USER = "user"
    LOCAL = "local"
    PROJECT = "project"
    MANAGED = "managed"
    PLUGIN = "plugin"
    EXTENSION = "extension"
    PATH = "path"
    SKILL = "skill"


class SourceStatus(enum.StrEnum):
    LOADED = "loaded"
    MISSING = "missing"
    ERROR = "error"


def _json_default(value: object) -> object:
    if isinstance(value, MappingProxyType):
        return dict(value)
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _plain_key(key: object) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, bool | int | float) or key is None:
        return json.dumps(key)
    return repr(key)


def _plain(value: object) -> object:
    if isinstance(value, dict | MappingProxyType):
        return {_plain_key(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    if isinstance(value, date | time):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    finite = not isinstance(value, float) or math.isfinite(value)
    if finite and (value is None or isinstance(value, str | int | float)):
        return value
    return repr(value)


def _dumps(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8", "backslashreplace")


def canonical_json(value: object) -> bytes:
    return _dumps(value)


def stable_json(value: object) -> bytes:
    try:
        return _dumps(value)
    except (TypeError, ValueError):
        return _dumps(_plain(value))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def frozen_mapping(mapping: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    return MappingProxyType(dict(mapping or {}))


def json_pointer(*parts: str) -> str:
    return "".join("/" + part.replace("~", "~0").replace("/", "~1") for part in parts)


@dataclass(frozen=True, slots=True)
class Location:
    path: Path
    pointer: str = ""
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"path": str(self.path), "pointer": self.pointer, "line": self.line}


@dataclass(frozen=True, slots=True)
class ConfigSource:
    client: Client
    scope: Scope
    path: Path
    project: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "client": self.client.value,
            "scope": self.scope.value,
            "path": str(self.path),
            "project": str(self.project) if self.project else None,
        }


@dataclass(frozen=True, slots=True)
class ServerEntry:
    name: str
    source: ConfigSource
    pointer: str
    transport: Transport
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=frozen_mapping, repr=False)
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=frozen_mapping, repr=False)
    cwd: str | None = None
    enabled: bool = True
    raw: Mapping[str, Any] = field(default_factory=frozen_mapping, repr=False)
    lines: Mapping[str, int] = field(default_factory=frozen_mapping, repr=False)
    shielded: bool = False
    shield_launcher: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.source.path}#{self.pointer}"

    @property
    def location(self) -> Location:
        return self.locate(self.pointer)

    def locate(self, pointer: str) -> Location:
        candidate = pointer
        while True:
            line = self.lines.get(candidate)
            if line is not None or not candidate:
                return Location(self.source.path, pointer, line)
            candidate = candidate.rsplit("/", 1)[0]

    @property
    def fingerprint(self) -> str:
        return sha256_hex(stable_json(self.raw))

    def display_target(self) -> str:
        if self.command is not None:
            return " ".join((self.command, *redact_args(self.args)))
        if self.url is not None:
            return redact_url(self.url)
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source.to_dict(),
            "pointer": self.pointer,
            "transport": self.transport.value,
            "command": self.command,
            "args": list(redact_args(self.args)),
            "env_keys": sorted(self.env),
            "url": redact_url(self.url) if self.url is not None else None,
            "header_keys": sorted(self.headers),
            "cwd": self.cwd,
            "enabled": self.enabled,
            "shielded": self.shielded,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    location: Location
    evidence: str = ""
    params: Mapping[str, str] = field(default_factory=frozen_mapping)

    @property
    def category(self) -> str:
        return self.rule_id.split("-", 1)[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.label,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "params": dict(self.params),
        }


@dataclass(frozen=True, slots=True)
class SourceRecord:
    source: ConfigSource
    status: SourceStatus
    error_code: str | None = None
    error_detail: str = ""
    server_count: int = 0
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.source.to_dict(),
            "status": self.status.value,
            "error_code": self.error_code,
            "error_detail": self.error_detail,
            "server_count": self.server_count,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class Inventory:
    servers: tuple[ServerEntry, ...]
    sources: tuple[SourceRecord, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    skills: tuple[ServerEntry, ...] = ()

    @property
    def entries(self) -> tuple[ServerEntry, ...]:
        return self.servers + self.skills

    @property
    def loaded_sources(self) -> tuple[SourceRecord, ...]:
        return tuple(r for r in self.sources if r.status is SourceStatus.LOADED)

    @property
    def failed_sources(self) -> tuple[SourceRecord, ...]:
        return tuple(r for r in self.sources if r.status is SourceStatus.ERROR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "generated_at": self.generated_at.isoformat(),
            "servers": [s.to_dict() for s in self.servers],
            "skills": [s.to_dict() for s in self.skills],
            "sources": [r.to_dict() for r in self.sources],
        }


class ToolKind(enum.StrEnum):
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    INSTRUCTIONS = "instructions"
    SKILL = "skill"


@dataclass(frozen=True, slots=True)
class TextField:
    label: str
    text: str
    location: Location


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    kind: ToolKind
    name: str
    description: str
    location: Location
    origin: str
    input_schema: Mapping[str, Any] = field(default_factory=frozen_mapping)
    annotations: Mapping[str, Any] = field(default_factory=frozen_mapping)
    fields: tuple[TextField, ...] = ()

    @property
    def identity(self) -> str:
        return f"{self.kind.value}:{self.name}"

    @property
    def fingerprint(self) -> str:
        return sha256_hex(
            stable_json(
                {
                    "kind": self.kind.value,
                    "name": self.name,
                    "description": self.description,
                    "input_schema": self.input_schema,
                    "annotations": self.annotations,
                }
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "description": self.description,
            "origin": self.origin,
            "location": self.location.to_dict(),
            "input_schema": dict(self.input_schema),
            "annotations": dict(self.annotations),
            "fingerprint": self.fingerprint,
        }


class SignalKind(enum.StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    FILE_READ = "file_read"
    SHELL_STRING = "shell_string"
    DYNAMIC_EVAL = "dynamic_eval"
    DECODE_EXEC = "decode_exec"
    ENV_DUMP = "env_dump"
    SENSITIVE_PATH = "sensitive_path"
    AGENT_CONFIG = "agent_config"
    SECRET = "secret"
    SUSPICIOUS_HOST = "suspicious_host"
    RAW_IP_URL = "raw_ip_url"
    INSTALL_SCRIPT = "install_script"
    DEPENDENCY_REMOTE = "dependency_remote"
    DEPENDENCY_LOOKALIKE = "dependency_lookalike"
    DEPENDENCY_UNPINNED = "dependency_unpinned"
    SETUP_EXEC = "setup_exec"
    NO_LOCKFILE = "no_lockfile"
    SKILL_SCRIPT = "skill_script"
    BROAD_TOOLS = "broad_tools"
    DOWNLOAD_EXEC = "download_exec"


CAPABILITY_SIGNALS = frozenset({SignalKind.PROCESS, SignalKind.NETWORK, SignalKind.FILE_READ})


@dataclass(frozen=True, slots=True)
class CodeSignal:
    kind: SignalKind
    location: Location
    evidence: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "location": self.location.to_dict(),
            "evidence": self.evidence,
            "detail": self.detail,
        }


class ToolGap(enum.StrEnum):
    REMOTE = "remote"
    NO_SOURCE = "no_source"
    BINARY = "binary"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ToolCollection:
    tools: tuple[ToolDefinition, ...] = ()
    origins: tuple[str, ...] = ()
    gap: ToolGap | None = None
    files_scanned: int = 0
    notes: tuple[str, ...] = ()
    signals: tuple[CodeSignal, ...] = ()

    @property
    def analyzed(self) -> bool:
        return bool(self.origins)

    @property
    def capabilities(self) -> tuple[SignalKind, ...]:
        found = {signal.kind for signal in self.signals if signal.kind in CAPABILITY_SIGNALS}
        return tuple(kind for kind in SignalKind if kind in found)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzed": self.analyzed,
            "gap": self.gap.value if self.gap else None,
            "origins": list(self.origins),
            "files_scanned": self.files_scanned,
            "notes": list(self.notes),
            "capabilities": [kind.value for kind in self.capabilities],
            "tools": [tool.to_dict() for tool in self.tools],
            "signals": [
                signal.to_dict() for signal in self.signals if signal.kind not in CAPABILITY_SIGNALS
            ],
        }
