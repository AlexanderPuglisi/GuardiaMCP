from __future__ import annotations

from collections.abc import Sequence
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
    ToolGap,
    Transport,
    canonical_json,
    frozen_mapping,
    sha256_hex,
)
from guardia.scanner import BaselineSummary, ScanContext, ScanReport, scan_inventory
from guardia.scanner.baseline import BASELINE_FILE, BaselineResult, BaselineStatus, run_baseline
from guardia.scanner.engine import LedgerSummary
from guardia.scanner.rules import RULES
from guardia.secure_store import KeyStoreError, Protector
from guardia.shield.wrapping import LauncherState, launcher_state

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


def _collect(server: ServerEntry, env: HostEnvironment) -> ToolCollection:
    try:
        return collect_tools(server, env)
    except Exception as exc:
        return ToolCollection(gap=ToolGap.ERROR, notes=(f"error:{type(exc).__name__}",))


def collect_all(
    servers: tuple[ServerEntry, ...], env: HostEnvironment
) -> dict[str, ToolCollection]:
    cache: dict[tuple[object, ...], ToolCollection] = {}
    collections: dict[str, ToolCollection] = {}
    for server in servers:
        key = _collection_key(server)
        if key not in cache:
            cache[key] = _collect(server, env)
        collections[server.key] = cache[key]
    return collections


def launcher_findings(servers: Sequence[ServerEntry]) -> dict[str, list[Finding]]:
    found: dict[str, list[Finding]] = {}
    for server in servers:
        if not server.shielded:
            continue
        state = launcher_state(server.shield_launcher)
        if state is LauncherState.CURRENT:
            continue
        rule = "G12-008" if state is LauncherState.OTHER else "G12-009"
        program = server.shield_launcher[0] if server.shield_launcher else ""
        found[server.key] = [
            Finding(
                rule_id=rule,
                severity=RULES[rule].severity,
                location=server.location,
                evidence=program,
                params=frozen_mapping({"server": server.name, "program": program}),
            )
        ]
    return found


def _baseline(
    env: HostEnvironment,
    options: AnalysisOptions,
    servers: list[ServerEntry],
    collections: dict[str, ToolCollection] | None,
) -> tuple[BaselineResult, str | None]:
    directory = env.data_dir if options.baseline else None
    try:
        result = run_baseline(
            directory,
            servers,
            collections or {},
            accept=options.accept_changes,
            write=options.write_baseline,
        )
    except Exception as exc:
        path = directory / BASELINE_FILE if directory is not None else None
        return BaselineResult(path=path, status=BaselineStatus.ERROR), type(exc).__name__
    return result, None


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
    result, baseline_error = _baseline(env, options, configured, collections)
    summary = BaselineSummary(
        str(result.path) if result.path is not None else None, result.status, result.written
    )
    ledger = Ledger(env.data_dir, options.protector) if options.ledger else None
    verification = ledger.verify() if ledger is not None else None
    extra_file_findings = list(result.file_findings)
    if ledger is not None and verification is not None:
        extra_file_findings.extend(ledger_findings(ledger, verification))
    extra: dict[str, list[Finding]] = {key: list(items) for key, items in result.findings.items()}
    for key, items in launcher_findings(configured).items():
        extra.setdefault(key, []).extend(items)
    report = scan_inventory(
        inventory,
        ScanContext(home=env.home),
        tools=collections,
        extra_findings=extra,
        extra_file_findings=extra_file_findings,
        baseline=summary,
    )
    if baseline_error is not None:
        report = replace(report, errors=(*report.errors, f"baseline: {baseline_error}"))
    if ledger is None or verification is None:
        return report
    recorded = False
    if options.write_ledger:
        try:
            ledger.append("scan", scan_event(report))
            recorded = True
        except (OSError, KeyStoreError, ValueError, TypeError):
            recorded = False
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
