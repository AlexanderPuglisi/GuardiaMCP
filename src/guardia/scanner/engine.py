from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from guardia import __version__
from guardia.model import (
    TOOL_NAME,
    Client,
    Finding,
    Inventory,
    Location,
    Scope,
    ServerEntry,
    Severity,
    SourceRecord,
    SourceStatus,
    ToolCollection,
    frozen_mapping,
)
from guardia.scanner.checks import SERVER_CHECKS, Check, ScanContext
from guardia.scanner.code_checks import code_findings
from guardia.scanner.rules import RULES
from guardia.scanner.tool_checks import (
    TOOL_CHECKS,
    ToolCheck,
    ToolContext,
    collection_notes,
    cross_server_findings,
)


def sort_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(
            findings,
            key=lambda f: (-f.severity, f.rule_id, f.location.line or 0, f.location.pointer),
        )
    )


@dataclass(frozen=True, slots=True)
class BaselineSummary:
    path: str | None
    status: str
    written: bool

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "status": self.status, "written": self.written}


@dataclass(frozen=True, slots=True)
class LedgerSummary:
    path: str
    records: int
    intact: bool
    tampered: bool
    anchor: str
    recorded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "records": self.records,
            "intact": self.intact,
            "tampered": self.tampered,
            "anchor": self.anchor,
            "recorded": self.recorded,
        }


@dataclass(frozen=True, slots=True)
class ServerReport:
    server: ServerEntry
    findings: tuple[Finding, ...]
    incomplete: bool = False
    tools: ToolCollection | None = None

    @property
    def risk(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        risk = self.risk
        return {
            "server": self.server.to_dict(),
            "risk": risk.label if risk is not None else None,
            "incomplete": self.incomplete,
            "findings": [f.to_dict() for f in self.findings],
            "tools": self.tools.to_dict() if self.tools is not None else None,
        }


@dataclass(frozen=True, slots=True)
class ScanReport:
    inventory: Inventory
    servers: tuple[ServerReport, ...]
    file_findings: tuple[Finding, ...]
    errors: tuple[str, ...]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tools_analyzed: bool = False
    baseline: BaselineSummary | None = None
    ledger: LedgerSummary | None = None

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(f for report in self.servers for f in report.findings) + self.file_findings

    @property
    def complete(self) -> bool:
        return not self.errors

    def counts(self) -> dict[Severity, int]:
        totals = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            totals[finding.severity] += 1
        return totals

    def risk_for(self, server: ServerEntry) -> Severity | None:
        for report in self.servers:
            if report.server.key == server.key:
                return report.risk
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": __version__,
            "generated_at": self.generated_at.isoformat(),
            "scope": ["configuration", "tools"] if self.tools_analyzed else ["configuration"],
            "baseline": self.baseline.to_dict() if self.baseline is not None else None,
            "ledger": self.ledger.to_dict() if self.ledger is not None else None,
            "complete": self.complete,
            "errors": list(self.errors),
            "summary": {severity.label: count for severity, count in self.counts().items()},
            "servers": [report.to_dict() for report in self.servers],
            "file_findings": [f.to_dict() for f in self.file_findings],
            "sources": [record.to_dict() for record in self.inventory.sources],
        }


def _file_finding(rule_id: str, record: SourceRecord, pointer: str = "", **params: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=RULES[rule_id].severity,
        location=Location(record.source.path, pointer),
        evidence=params.get("detail", ""),
        params=frozen_mapping(params),
    )


def source_findings(records: Sequence[SourceRecord]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for record in records:
        if record.status is SourceStatus.ERROR:
            findings.append(
                _file_finding(
                    "G12-006",
                    record,
                    reason=record.error_code or "",
                    detail=record.error_detail,
                )
            )
        for warning in record.warnings:
            code, _, detail = warning.partition(":")
            if code == "duplicate_key":
                findings.append(_file_finding("G12-004", record, key=detail, detail=detail))
            elif code == "reference_outside_root":
                findings.append(_file_finding("G12-005", record, reference=detail, detail=detail))
    return sort_findings(findings)


def conflicting_definitions(servers: Sequence[ServerEntry]) -> dict[str, list[Finding]]:
    by_name: dict[str, list[ServerEntry]] = defaultdict(list)
    for server in servers:
        by_name[server.name.strip().lower()].append(server)
    extra: dict[str, list[Finding]] = defaultdict(list)
    for group in by_name.values():
        fingerprints = {server.fingerprint for server in group}
        if len(fingerprints) < 2:
            continue
        for server in group:
            extra[server.key].append(
                Finding(
                    rule_id="G12-003",
                    severity=RULES["G12-003"].severity,
                    location=server.location,
                    params=frozen_mapping(
                        {"server": server.name, "variants": str(len(fingerprints))}
                    ),
                )
            )
    return extra


def _run_tool_checks(
    server: ServerEntry,
    collection: ToolCollection,
    tool_checks: Sequence[ToolCheck],
    errors: list[str],
) -> tuple[list[Finding], bool]:
    findings: list[Finding] = collection_notes(server, collection)
    incomplete = False
    try:
        findings.extend(code_findings(server, collection))
    except Exception as exc:
        incomplete = True
        errors.append(f"code_findings@{server.key}: {type(exc).__name__}")
    for tool in collection.tools:
        for check in tool_checks:
            try:
                findings.extend(check(ToolContext(server, tool)))
            except Exception as exc:
                incomplete = True
                errors.append(
                    f"{check.__name__}@{server.key}#{tool.identity}: {type(exc).__name__}"
                )
    return findings, incomplete


def scan_inventory(
    inventory: Inventory,
    context: ScanContext | None = None,
    checks: Sequence[Check] = SERVER_CHECKS,
    *,
    tools: Mapping[str, ToolCollection] | None = None,
    tool_checks: Sequence[ToolCheck] = TOOL_CHECKS,
    extra_findings: Mapping[str, Sequence[Finding]] | None = None,
    extra_file_findings: Sequence[Finding] = (),
    baseline: BaselineSummary | None = None,
) -> ScanReport:
    context = context or ScanContext()
    configured = [s for s in inventory.servers if s.source.client is not Client.MANUAL]
    cross = conflicting_definitions(configured)
    cross_tools = cross_server_findings(inventory.entries, tools or {})
    reports: list[ServerReport] = []
    errors: list[str] = []
    for server in inventory.entries:
        findings: list[Finding] = list(cross.get(server.key, []))
        findings.extend(cross_tools.get(server.key, []))
        findings.extend((extra_findings or {}).get(server.key, []))
        incomplete = False
        if server.source.client is not Client.MANUAL and server.source.scope is not Scope.SKILL:
            for check in checks:
                try:
                    findings.extend(check(server, context))
                except Exception as exc:
                    incomplete = True
                    errors.append(f"{check.__name__}@{server.key}: {type(exc).__name__}")
        collection = tools.get(server.key) if tools is not None else None
        if collection is not None:
            tool_findings, tools_incomplete = _run_tool_checks(
                server, collection, tool_checks, errors
            )
            findings.extend(tool_findings)
            incomplete = incomplete or tools_incomplete
        reports.append(ServerReport(server, sort_findings(findings), incomplete, collection))
    ordered = sorted(
        reports,
        key=lambda r: (-(r.risk if r.risk is not None else -1), r.server.name.lower()),
    )
    return ScanReport(
        inventory=inventory,
        servers=tuple(ordered),
        file_findings=sort_findings([*source_findings(inventory.sources), *extra_file_findings]),
        errors=tuple(errors),
        tools_analyzed=tools is not None,
        baseline=baseline,
    )
