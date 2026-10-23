from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from guardia.extract import collect_tools
from guardia.extract.sources import server_base
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger, Verification
from guardia.model import (
    Client,
    ConfigSource,
    Finding,
    Inventory,
    Location,
    Scope,
    ServerEntry,
    ToolCollection,
    Transport,
    canonical_json,
    frozen_mapping,
    sha256_hex,
)
from guardia.scanner import BaselineSummary, ScanContext, ScanReport, scan_inventory
from guardia.scanner.baseline import run_baseline
from guardia.scanner.engine import LedgerSummary
from guardia.scanner.rules import RULES
from guardia.secure_store import Protector

MAX_LEDGER_FINDINGS = 500


@dataclass(frozen=True, slots=True)
class AnalysisOptions:
    discovery: DiscoveryOptions = field(default_factory=DiscoveryOptions)
    paths: tuple[Path, ...] = ()
    tools: bool = True
    baseline: bool = True
    accept_changes: bool = False
    write_baseline: bool = True
    ledger: bool = True
    write_ledger: bool = True
    protector: Protector | None = None


def manual_server(path: Path) -> ServerEntry:
    absolute = path.absolute()
    return ServerEntry(
        name=absolute.name or str(absolute),
        source=ConfigSource(Client.MANUAL, Scope.PATH, absolute),
        pointer="",
        transport=Transport.UNKNOWN,
    )


def _collection_key(server: ServerEntry) -> tuple[object, ...]:
    if server.source.scope in (Scope.EXTENSION, Scope.PLUGIN):
        anchor = str(server_base(server))
    elif server.source.scope in (Scope.PATH, Scope.SKILL):
        anchor = str(server.source.path)
    else:
        anchor = ""
    return (anchor, server.command, server.args, server.cwd, server.url, server.transport)


def collect_all(
    servers: tuple[ServerEntry, ...], env: HostEnvironment
) -> dict[str, ToolCollection]:
    cache: dict[tuple[object, ...], ToolCollection] = {}
    collections: dict[str, ToolCollection] = {}
    for server in servers:
        key = _collection_key(server)
        if key not in cache:
            cache[key] = collect_tools(server, env)
        collections[server.key] = cache[key]
    return collections


def ledger_findings(ledger: Ledger, verification: Verification) -> list[Finding]:
    if verification.intact:
        return []
    rule = "G13-001" if verification.tampered else "G13-002"
    first = verification.issues[0]
    problems = ", ".join(sorted({issue.problem.value for issue in verification.issues}))
    return [
        Finding(
            rule_id=rule,
            severity=RULES[rule].severity,
            location=Location(ledger.path, "", first.line),
            evidence=problems,
            params=frozen_mapping({"path": str(ledger.path), "problems": problems}),
        )
    ]


def scan_event(report: ScanReport) -> dict[str, Any]:
    findings = [
        {
            "rule": finding.rule_id,
            "severity": finding.severity.label,
            "entry": entry.server.name,
            "path": str(finding.location.path),
            "line": finding.location.line,
        }
        for entry in report.servers
        for finding in entry.findings
    ]
    return {
        "complete": report.complete,
        "summary": {severity.label: count for severity, count in report.counts().items()},
        "servers": len(report.inventory.servers),
        "skills": len(report.inventory.skills),
        "baseline": report.baseline.status if report.baseline is not None else None,
        "findings": findings[:MAX_LEDGER_FINDINGS],
        "findings_total": len(findings),
        "report_sha256": sha256_hex(canonical_json(report.to_dict())),
    }


def analyze(env: HostEnvironment, options: AnalysisOptions | None = None) -> ScanReport:
    options = options or AnalysisOptions()
    inventory = discover(env, options.discovery)
    manual = tuple(manual_server(path) for path in options.paths)
    if manual:
        inventory = Inventory(
            inventory.servers + manual,
            inventory.sources,
            inventory.generated_at,
            skills=inventory.skills,
        )
    collections = collect_all(inventory.entries, env) if options.tools else None
    configured = [s for s in inventory.entries if s.source.client is not Client.MANUAL]
    result = run_baseline(
        env.data_dir if options.baseline else None,
        configured,
        collections or {},
        accept=options.accept_changes,
        write=options.write_baseline,
    )
    summary = BaselineSummary(
        str(result.path) if result.path is not None else None, result.status, result.written
    )
    ledger = Ledger(env.data_dir, options.protector) if options.ledger else None
    verification = ledger.verify() if ledger is not None else None
    extra_file_findings = list(result.file_findings)
    if ledger is not None and verification is not None:
        extra_file_findings.extend(ledger_findings(ledger, verification))
    report = scan_inventory(
        inventory,
        ScanContext(home=env.home),
        tools=collections,
        extra_findings=result.findings,
        extra_file_findings=extra_file_findings,
        baseline=summary,
    )
    if ledger is None or verification is None:
        return report
    recorded = False
    if options.write_ledger:
        ledger.append("scan", scan_event(report))
        recorded = True
    after = ledger.verify() if recorded else verification
    return replace(
        report,
        ledger=LedgerSummary(
            path=str(ledger.path),
            records=after.records,
            intact=verification.intact,
            tampered=verification.tampered,
            anchor=after.anchor,
            recorded=recorded,
        ),
    )
