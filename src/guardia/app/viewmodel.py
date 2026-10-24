from __future__ import annotations

from typing import Any

from guardia import __version__
from guardia.display import safe_text
from guardia.i18n import Translator, load_messages
from guardia.model import Client, Finding, Scope, ServerEntry, Severity
from guardia.render.terminal import (
    PARAM_WIDTH,
    baseline_line,
    coverage_line,
    coverage_summary,
    finding_evidence,
    finding_params,
    ledger_line,
    severity_label,
)
from guardia.scanner import ScanReport, ServerReport

PRIORITY_LIMIT = 8
RUG_PULL_RULES = frozenset({"G03-001", "G03-002", "G03-003", "G03-004", "G03-006"})


def ui_strings(t: Translator) -> dict[str, str]:
    messages = load_messages(t.language)
    strings = {key[3:]: value for key, value in messages.items() if key.startswith("ui.")}
    for severity in Severity:
        strings[f"severity.{severity.label}"] = severity_label(severity, t)
    for key in ("scan.where", "scan.found", "scan.why", "scan.fix", "scan.not_safe"):
        strings[key] = t(key)
    return strings


def _entry_type(server: ServerEntry) -> str:
    if server.source.scope is Scope.SKILL:
        return "skill"
    if server.source.client is Client.MANUAL:
        return "manual"
    return "server"


def _text(value: object, width: int | None = None) -> str:
    return safe_text(str(value), width)


def finding_view(finding: Finding, t: Translator, entry_id: str, entry_name: str) -> dict[str, Any]:
    params = finding_params(finding, t)
    location = finding.location
    where = _text(location.path)
    if location.line is not None:
        where += ", " + t("scan.line", line=location.line)
    if location.pointer:
        where += f" ({_text(location.pointer, PARAM_WIDTH)})"
    if params.get("tool"):
        key = "skills.field" if params.get("kind") == "skill" else "scan.tool_field"
        where += " — " + t(key, tool=params["tool"], field=params.get("field", ""))
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.label,
        "severity_rank": int(finding.severity),
        "severity_label": severity_label(finding.severity, t),
        "title": t(f"rules.{finding.rule_id}.title", **params),
        "why": t(f"rules.{finding.rule_id}.why", **params),
        "fix": t(f"rules.{finding.rule_id}.fix", **params),
        "where": where,
        "evidence": _text(finding_evidence(finding, t), PARAM_WIDTH),
        "path": _text(location.path),
        "line": location.line,
        "entry_id": entry_id,
        "entry_name": _text(entry_name, 80),
        "rug_pull": finding.rule_id in RUG_PULL_RULES,
    }


def entry_view(index: int, report: ServerReport, t: Translator) -> dict[str, Any]:
    server = report.server
    entry_id = f"e{index}"
    risk = report.risk
    tools = report.tools
    capabilities = (
        [t(f"capability.{kind.value}") for kind in tools.capabilities] if tools is not None else []
    )
    return {
        "id": entry_id,
        "name": _text(server.name, 80),
        "type": _entry_type(server),
        "type_label": t(f"ui.type_{_entry_type(server)}"),
        "client": t(f"client.{server.source.client.value}"),
        "scope": t(f"scope.{server.source.scope.value}"),
        "transport": server.transport.value if _entry_type(server) == "server" else "",
        "path": _text(server.source.path),
        "target": _text(server.display_target(), 200),
        "risk": risk.label if risk is not None else ("none" if report.incomplete else "ok"),
        "risk_rank": int(risk) if risk is not None else -1,
        "risk_label": (
            "?"
            if report.incomplete
            else severity_label(risk, t)
            if risk is not None
            else t("ui.risk_ok")
        ),
        "incomplete": report.incomplete,
        "enabled": server.enabled,
        "coverage": coverage_line(report, t, app=True) or "",
        "capabilities": capabilities,
        "tools": len(tools.tools) if tools is not None else 0,
        "findings": [finding_view(f, t, entry_id, server.name) for f in report.findings],
    }


def report_view(report: ScanReport, t: Translator, seconds: float) -> dict[str, Any]:
    entries = [entry_view(index, entry, t) for index, entry in enumerate(report.servers)]
    findings = [finding for entry in entries for finding in entry["findings"]]
    file_findings = [finding_view(f, t, "", "") for f in report.file_findings]
    priority = sorted(
        (f for f in [*findings, *file_findings] if f["severity_rank"] >= Severity.MEDIUM),
        key=lambda f: -int(f["severity_rank"]),
    )[:PRIORITY_LIMIT]
    counts = report.counts()
    ledger = report.ledger
    baseline = report.baseline
    return {
        "version": __version__,
        "generated_at": report.generated_at.isoformat(timespec="seconds"),
        "seconds": round(seconds, 1),
        "complete": report.complete,
        "errors": len(report.errors),
        "summary": [
            {"severity": s.label, "label": severity_label(s, t), "count": counts[s]}
            for s in sorted(Severity, reverse=True)
        ],
        "total": len(report.findings),
        "entries": entries,
        "findings": findings,
        "file_findings": file_findings,
        "priority": priority,
        "has_rug_pull": any(f["rug_pull"] for f in [*findings, *file_findings]),
        "coverage": coverage_summary(report, t, app=True),
        "coverage_gaps": not report.tools_analyzed
        or any(entry.tools is not None and not entry.tools.analyzed for entry in report.servers),
        "baseline": {
            "active": baseline is not None and baseline.path is not None,
            "status": baseline.status if baseline is not None else "disabled",
            "line": baseline_line(report, t) or "",
            "entries": sum(1 for _ in report.servers),
        },
        "ledger": {
            "active": ledger is not None,
            "intact": ledger.intact if ledger is not None else False,
            "tampered": ledger.tampered if ledger is not None else False,
            "records": ledger.records if ledger is not None else 0,
            "anchor": ledger.anchor if ledger is not None else "",
            "line": ledger_line(report, t) or "",
        },
        "counts": {
            "servers": sum(1 for e in entries if e["type"] == "server"),
            "skills": sum(1 for e in entries if e["type"] == "skill"),
        },
    }
