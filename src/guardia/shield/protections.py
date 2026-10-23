from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from guardia.extract.documents import tools_from_document
from guardia.model import (
    Client,
    ConfigSource,
    Finding,
    Scope,
    ServerEntry,
    Severity,
    Transport,
    sha256_hex,
    stable_json,
)
from guardia.redact import REDACTED, SECRET_VALUE
from guardia.scanner.tool_checks import TOOL_CHECKS, ToolContext, check_text_fields
from guardia.shield.patterns import leaves
from guardia.shield.rules import Sensitivity

SHIELD_SOURCE = Path("guardia-shield")
MAX_RESULT_SCAN = 1_000_000
RESULT_IGNORED_RULES = frozenset({"G01-006"})
RESULT_MINIMUM = Severity.MEDIUM
THRESHOLDS = {
    Sensitivity.CRITICAL: Severity.CRITICAL,
    Sensitivity.HIGH: Severity.HIGH,
    Sensitivity.MEDIUM: Severity.MEDIUM,
}
CREDENTIAL = re.compile(
    r"\b(?:passwords?|passwd|passphrase|passcode|parola d'ordine|pin(?: code)?|codice pin|"
    r"otp|one[- ]time (?:code|password)|codice (?:otp|di verifica)|2fa|mfa|"
    r"api[ _-]?key|secret[ _-]?key|access[ _-]?token|auth(?:entication)?[ _-]?token|"
    r"chiave (?:segreta|privata|api)|private[ _-]?key|seed phrase|recovery phrase|"
    r"frase di recupero|mnemonic|credit card|card number|numero (?:della |di )?carta|"
    r"cvv|cvc|iban|social security|ssn)\b",
    re.IGNORECASE,
)


def _server(name: str) -> ServerEntry:
    return ServerEntry(
        name=name,
        source=ConfigSource(Client.MANUAL, Scope.PATH, SHIELD_SOURCE),
        pointer="",
        transport=Transport.STDIO,
    )


def tool_fingerprint(tool: Mapping[str, Any]) -> str:
    return sha256_hex(stable_json({key: value for key, value in tool.items() if key != "_meta"}))


def tool_findings(server: str, tool: Mapping[str, Any]) -> list[Finding]:
    entry = _server(server)
    definitions = tools_from_document(
        SHIELD_SOURCE / "tools.json", {"tools": [dict(tool)]}, "shield"
    )
    return [
        finding
        for definition in definitions
        for check in TOOL_CHECKS
        for finding in check(ToolContext(entry, definition))
    ]


def instructions_findings(server: str, text: str) -> list[Finding]:
    entry = _server(server)
    definitions = tools_from_document(
        SHIELD_SOURCE / "server.json", {"instructions": text}, "shield"
    )
    return [
        finding
        for definition in definitions
        for finding in check_text_fields(ToolContext(entry, definition))
    ]


def result_text(value: Any) -> str:
    parts: list[str] = []
    size = 0
    for leaf in leaves(value):
        parts.append(leaf.text)
        size += len(leaf.text) + 1
        if size >= MAX_RESULT_SCAN:
            break
    return "\n".join(parts)[:MAX_RESULT_SCAN]


def result_findings(server: str, tool: str, value: Any) -> list[Finding]:
    text = result_text(value)
    if not text.strip():
        return []
    entry = _server(server)
    definitions = tools_from_document(
        SHIELD_SOURCE / "result.json",
        {"tools": [{"name": tool or "result", "description": text}]},
        "shield",
    )
    return [
        finding
        for definition in definitions
        for finding in check_text_fields(ToolContext(entry, definition))
        if finding.rule_id not in RESULT_IGNORED_RULES and finding.severity >= RESULT_MINIMUM
    ]


def over_threshold(findings: list[Finding], sensitivity: Sensitivity) -> list[Finding]:
    threshold = THRESHOLDS.get(sensitivity)
    if threshold is None:
        return []
    return [finding for finding in findings if finding.severity >= threshold]


def rule_ids(findings: list[Finding], limit: int = 5) -> list[str]:
    return sorted({finding.rule_id for finding in findings})[:limit]


def has_secret(value: Any) -> bool:
    return any(SECRET_VALUE.search(leaf.text) for leaf in leaves(value))


def credential_request(value: Any) -> str | None:
    for leaf in leaves(value):
        for text in (leaf.text, *leaf.keys):
            match = CREDENTIAL.search(text)
            if match:
                return match.group(0)
    return None


def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return SECRET_VALUE.sub(REDACTED, value)
    if isinstance(value, dict):
        return {key: redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value
