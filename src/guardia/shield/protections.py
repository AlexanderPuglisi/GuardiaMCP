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
    r"\b(?:passwords?|passwd|passphrase|passcode|parola d'ordine|pin[ _-]?code|codice pin|"
    r"pin number|numero pin|otp|one[- ]time (?:code|password)|codice (?:otp|di verifica)|"
    r"2fa|mfa|api[ _-]?key|secret[ _-]?key|access[ _-]?token|auth(?:entication)?[ _-]?token|"
    r"chiave (?:segreta|privata|api)|private[ _-]?key|seed phrase|recovery phrase|"
    r"frase di recupero|mnemonic|credit card|card number|numero (?:della |di )?carta|"
    r"cvv|cvc|iban|social security|ssn)\b",
    re.IGNORECASE,
)
PIN_ACRONYM = re.compile(r"\bPIN\b")
PIN_FIELD = re.compile(r"pin(?: (?:code|number))?", re.IGNORECASE)
CAMEL_CASE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
ELICITATION = "elicitation/create"
URL_MODE = "url"
MAX_FIELDS = 100
MAX_INPUT_REQUESTS = 50


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
    for leaf in leaves(value, include_keys=True):
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
    return any(SECRET_VALUE.search(leaf.text) for leaf in leaves(value, include_keys=True))


def _field_words(name: str) -> str:
    return CAMEL_CASE.sub(" ", name).replace("_", " ").replace("-", " ").strip()


def _field_name(name: str) -> str | None:
    words = _field_words(name)
    if PIN_FIELD.fullmatch(words) or CREDENTIAL.search(words) or PIN_ACRONYM.search(name):
        return name
    return None


def _labels(params: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    message = params.get("message")
    texts = [message] if isinstance(message, str) else []
    schema = params.get("requestedSchema")
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict):
        return [], texts
    names: list[str] = []
    for name, spec in list(properties.items())[:MAX_FIELDS]:
        names.append(str(name))
        if isinstance(spec, dict):
            texts.extend(
                spec[key] for key in ("title", "description") if isinstance(spec.get(key), str)
            )
    return names, texts


def credential_request(params: Any) -> str | None:
    if not isinstance(params, dict) or params.get("mode") == URL_MODE:
        return None
    names, texts = _labels(params)
    for text in texts:
        match = CREDENTIAL.search(text) or PIN_ACRONYM.search(text)
        if match:
            return match.group(0)
    for name in names:
        found = _field_name(name)
        if found is not None:
            return found
    return None


def elicitations(method: str, params: Any) -> list[Any]:
    return [params] if method == ELICITATION else []


def input_elicitations(requests: Any) -> list[Any]:
    if not isinstance(requests, dict):
        return []
    return [
        item.get("params")
        for item in list(requests.values())[:MAX_INPUT_REQUESTS]
        if isinstance(item, dict) and item.get("method") == ELICITATION
    ]


def redact_secrets(value: Any) -> Any:
    if isinstance(value, str):
        return SECRET_VALUE.sub(REDACTED, value)
    if isinstance(value, dict):
        return {
            (SECRET_VALUE.sub(REDACTED, key) if isinstance(key, str) else key): redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value
