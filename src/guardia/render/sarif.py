from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from guardia import __version__
from guardia.i18n import Translator
from guardia.model import Finding, Severity, canonical_json, sha256_hex
from guardia.render.terminal import finding_params
from guardia.scanner import RULES, ScanReport

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
PLACEHOLDER = re.compile(r"\{\{?(\w+)\}?\}")


def _generic(text: str) -> str:
    return PLACEHOLDER.sub("…", text)


def _artifact(path: Path, base: Path | None) -> dict[str, str]:
    if base is not None:
        try:
            relative = path.resolve().relative_to(base.resolve())
        except (ValueError, OSError):
            relative = None
        if relative is not None:
            return {"uri": relative.as_posix(), "uriBaseId": "SRCROOT"}
    try:
        return {"uri": path.resolve().as_uri()}
    except (ValueError, OSError):
        return {"uri": path.as_posix()}


def _rule(rule_id: str, t: Translator) -> dict[str, Any]:
    rule = RULES[rule_id]
    return {
        "id": rule_id,
        "name": rule_id.replace("-", ""),
        "shortDescription": {"text": _generic(t(f"rules.{rule_id}.title"))},
        "fullDescription": {"text": _generic(t(f"rules.{rule_id}.why"))},
        "help": {"text": _generic(t(f"rules.{rule_id}.fix"))},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "properties": {
            "security-severity": SECURITY_SEVERITY[rule.severity],
            "tags": ["security", "mcp", t(f"category.{rule.category}")],
        },
    }


def _result(
    finding: Finding, entry: str, index: dict[str, int], t: Translator, base: Path | None
) -> dict[str, Any]:
    params = finding_params(finding, t)
    title = t(f"rules.{finding.rule_id}.title", **params)
    why = t(f"rules.{finding.rule_id}.why", **params)
    physical: dict[str, Any] = {"artifactLocation": _artifact(finding.location.path, base)}
    if finding.location.line is not None:
        physical["region"] = {"startLine": finding.location.line}
    identity = canonical_json(
        [
            finding.rule_id,
            os.path.normcase(str(finding.location.path)),
            finding.location.pointer,
            finding.evidence,
            entry,
        ]
    )
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": index[finding.rule_id],
        "level": LEVELS[finding.severity],
        "message": {"text": f"{title}: {why}"},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"guardiaFindingHash/v1": sha256_hex(identity)},
        "properties": {
            "security-severity": SECURITY_SEVERITY[finding.severity],
            "severity": finding.severity.label,
            "entry": entry,
        },
    }
    if finding.location.pointer:
        result["locations"][0]["logicalLocations"] = [
            {"fullyQualifiedName": finding.location.pointer}
        ]
    return result


def build_sarif(report: ScanReport, t: Translator, base: Path | None = None) -> dict[str, Any]:
    ordered = sorted(RULES)
    index = {rule_id: position for position, rule_id in enumerate(ordered)}
    results = [
        _result(finding, entry.server.name, index, t, base)
        for entry in report.servers
        for finding in entry.findings
    ]
    results.extend(_result(finding, "", index, t, base) for finding in report.file_findings)
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Guardia MCP",
                "version": __version__,
                "semanticVersion": __version__,
                "organization": "Alexander Puglisi",
                "rules": [_rule(rule_id, t) for rule_id in ordered],
            }
        },
        "invocations": [
            {
                "executionSuccessful": report.complete,
                "endTimeUtc": report.generated_at.isoformat(),
            }
        ],
        "results": results,
        "columnKind": "unicodeCodePoints",
    }
    if base is not None:
        run["originalUriBaseIds"] = {"SRCROOT": {"uri": base.resolve().as_uri() + "/"}}
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
