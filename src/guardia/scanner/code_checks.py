from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path

from guardia.model import (
    CodeSignal,
    Finding,
    Location,
    ServerEntry,
    Severity,
    SignalKind,
    ToolCollection,
    frozen_mapping,
)
from guardia.scanner.rules import RULES

SIGNAL_RULES: dict[SignalKind, str] = {
    SignalKind.DECODE_EXEC: "G05-009",
    SignalKind.SHELL_STRING: "G05-010",
    SignalKind.DYNAMIC_EVAL: "G05-011",
    SignalKind.SECRET: "G06-007",
    SignalKind.ENV_DUMP: "G06-008",
    SignalKind.SENSITIVE_PATH: "G07-005",
    SignalKind.AGENT_CONFIG: "G07-006",
    SignalKind.SUSPICIOUS_HOST: "G09-011",
    SignalKind.RAW_IP_URL: "G09-012",
    SignalKind.INSTALL_SCRIPT: "G10-006",
    SignalKind.DEPENDENCY_REMOTE: "G10-007",
    SignalKind.DEPENDENCY_LOOKALIKE: "G10-008",
    SignalKind.DEPENDENCY_UNPINNED: "G10-009",
    SignalKind.SETUP_EXEC: "G10-010",
    SignalKind.NO_LOCKFILE: "G10-011",
    SignalKind.SKILL_SCRIPT: "G14-001",
    SignalKind.BROAD_TOOLS: "G14-002",
    SignalKind.DOWNLOAD_EXEC: "G14-003",
}


def _finding(
    rule_id: str,
    server: ServerEntry,
    location: Location,
    evidence: str,
    severity: Severity | None = None,
    **params: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity if severity is not None else RULES[rule_id].severity,
        location=location,
        evidence=evidence[:160],
        params=frozen_mapping({"server": server.name, **params}),
    )


def _network_files(signals: tuple[CodeSignal, ...]) -> set[Path]:
    return {s.location.path for s in signals if s.kind is SignalKind.NETWORK}


def _severity(signal: CodeSignal, networked: set[Path]) -> Severity | None:
    if signal.kind is SignalKind.SENSITIVE_PATH and signal.location.path in networked:
        return Severity.CRITICAL
    if signal.kind is SignalKind.INSTALL_SCRIPT and signal.detail == "dangerous":
        return Severity.HIGH
    if signal.kind is SignalKind.DOWNLOAD_EXEC and signal.detail == "instructions":
        return Severity.MEDIUM
    return None


def code_findings(server: ServerEntry, collection: ToolCollection) -> Iterator[Finding]:
    networked = _network_files(collection.signals)
    grouped: dict[tuple[str, Severity], list[CodeSignal]] = defaultdict(list)
    for signal in collection.signals:
        rule_id = SIGNAL_RULES.get(signal.kind)
        if rule_id is None:
            continue
        severity = _severity(signal, networked) or RULES[rule_id].severity
        grouped[(rule_id, severity)].append(signal)
    for (rule_id, severity), signals in grouped.items():
        first = signals[0]
        others = sorted({s.location.path.name for s in signals[1:]} - {first.location.path.name})
        yield _finding(
            rule_id,
            server,
            first.location,
            first.evidence,
            severity,
            found=first.evidence,
            detail=first.detail,
            count=str(len(signals)),
            files=", ".join([first.location.path.name, *others][:6]),
        )
