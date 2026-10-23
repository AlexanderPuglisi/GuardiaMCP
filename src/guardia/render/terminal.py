from __future__ import annotations

import textwrap

from guardia import __version__
from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.inventory.parsers import project_key
from guardia.model import Finding, Inventory, ServerEntry, Severity, SourceRecord, SourceStatus
from guardia.scanner import ScanReport, ServerReport

NAME_WIDTH = 48
TARGET_WIDTH = 160
KEYS_WIDTH = 160
PARAM_WIDTH = 200
WRAP_WIDTH = 100
NO_RISK = "—"
UNKNOWN_RISK = "?"


def translate_warning(warning: str, t: Translator) -> str:
    code, _, detail = warning.partition(":")
    key = f"warning.{code}"
    if not t.has(key):
        return t("warning.unknown", detail=safe_text(warning, KEYS_WIDTH))
    return t(key, detail=safe_text(detail, KEYS_WIDTH))


def severity_label(severity: Severity | None, t: Translator) -> str:
    return NO_RISK if severity is None else t(f"severity.{severity.label}")


def _source_label(client: str, scope: str, t: Translator) -> str:
    return f"{t('client.' + client)} · {t('scope.' + scope)}"


def _source_header(record: SourceRecord, t: Translator) -> str:
    source = record.source
    label = _source_label(source.client.value, source.scope.value, t)
    return f"{label} · {safe_text(str(source.path))}"


def _risk_badge(server: ServerEntry, report: ScanReport | None, t: Translator) -> str:
    if report is None:
        return ""
    server_report = next((r for r in report.servers if r.server.key == server.key), None)
    if server_report is None or server_report.incomplete:
        return f"[{UNKNOWN_RISK}] "
    return f"[{severity_label(server_report.risk, t)}] "


def _server_lines(
    server: ServerEntry, record: SourceRecord, t: Translator, report: ScanReport | None
) -> list[str]:
    marker = "●" if server.enabled else "○"
    name = safe_text(server.name, NAME_WIDTH)
    target = safe_text(server.display_target(), TARGET_WIDTH) or t("inventory.no_target")
    line = (
        f"  {marker} {_risk_badge(server, report, t)}{name}  [{server.transport.value}]  {target}"
    )
    if not server.enabled:
        line += f"  ({t('inventory.disabled')})"
    lines = [line]
    if server.source.scope is not record.source.scope:
        lines.append(f"      {t('scope.' + server.source.scope.value)}")
    if server.source.project is not None and record.source.project is None:
        lines.append("      " + t("inventory.project", path=safe_text(str(server.source.project))))
    if server.env:
        keys = safe_text(", ".join(sorted(server.env)), KEYS_WIDTH)
        lines.append("      " + t("inventory.env_keys", keys=keys))
    if server.headers:
        keys = safe_text(", ".join(sorted(server.headers)), KEYS_WIDTH)
        lines.append("      " + t("inventory.header_keys", keys=keys))
    return lines


def _visible(record: SourceRecord, all_sources: bool) -> bool:
    if all_sources:
        return True
    if record.status is SourceStatus.MISSING:
        return False
    return record.status is SourceStatus.ERROR or record.server_count > 0 or bool(record.warnings)


def _skill_lines(inventory: Inventory, t: Translator, report: ScanReport | None) -> list[str]:
    if not inventory.skills:
        return []
    lines = [t("skills.title", count=len(inventory.skills))]
    flagged: list[str] = []
    clean: list[str] = []
    for skill in inventory.skills:
        badge = _risk_badge(skill, report, t)
        name = safe_text(skill.name, NAME_WIDTH)
        if report is None or badge == f"[{NO_RISK}] ":
            clean.append(name)
            continue
        label = _source_label(skill.source.client.value, skill.source.scope.value, t)
        flagged.append(f"  ● {badge}{name}  · {label} · {safe_text(str(skill.source.path))}")
    if flagged:
        lines.append(t("skills.flagged"))
        lines.extend(flagged)
    if clean:
        unique = sorted(set(clean), key=str.lower)
        text = t("skills.clean", count=len(clean), names=", ".join(unique))
        lines.extend(textwrap.wrap(text, WRAP_WIDTH, initial_indent="  ", subsequent_indent="  "))
    lines.append("")
    return lines


def render_inventory(
    inventory: Inventory,
    t: Translator,
    *,
    all_sources: bool = False,
    report: ScanReport | None = None,
) -> str:
    servers_by_file: dict[str, list[ServerEntry]] = {}
    for server in inventory.servers:
        servers_by_file.setdefault(project_key(server.source.path), []).append(server)

    lines = [t("app.banner", version=__version__), t("inventory.title"), ""]
    for record in inventory.sources:
        if not _visible(record, all_sources):
            continue
        lines.append(_source_header(record, t))
        if record.source.project is not None:
            lines.append("  " + t("inventory.project", path=safe_text(str(record.source.project))))
        if record.status is SourceStatus.ERROR:
            message = t(f"error.{record.error_code}")
            detail = (
                f" ({safe_text(record.error_detail, KEYS_WIDTH)})" if record.error_detail else ""
            )
            lines.append(f"  ✗ {t('status.error')}: {message}{detail}")
        elif record.status is SourceStatus.MISSING:
            lines.append(f"  · {t('status.missing')}")
        for server in servers_by_file.get(project_key(record.source.path), []):
            lines.extend(_server_lines(server, record, t, report))
        lines.extend(f"  ! {translate_warning(w, t)}" for w in record.warnings)
        lines.append("")

    if not inventory.servers:
        lines.extend([t("inventory.no_servers"), ""])
    lines.extend(_skill_lines(inventory, t, report))
    enabled = sum(1 for s in inventory.servers if s.enabled)
    lines.append(
        t(
            "inventory.summary",
            servers=len(inventory.servers),
            enabled=enabled,
            files=len(inventory.loaded_sources),
        )
    )
    if inventory.failed_sources:
        lines.append(t("inventory.errors", count=len(inventory.failed_sources)))
    if report is not None:
        lines.append(t("inventory.legend", none=NO_RISK, unknown=UNKNOWN_RISK))
        lines.append(t("inventory.risk_note"))
    lines.append(t("inventory.read_only"))
    return "\n".join(lines) + "\n"


def finding_params(finding: Finding, t: Translator) -> dict[str, str]:
    params = {key: safe_text(value, PARAM_WIDTH) for key, value in finding.params.items()}
    if "reason" in params:
        params["reason"] = t(f"error.{params['reason']}")
    if params.get("version") == "":
        params["version"] = t("scan.no_version")
    return params


def _wrapped(label: str, text: str) -> list[str]:
    prefix = f"     {label}: "
    return textwrap.wrap(
        text,
        width=WRAP_WIDTH,
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [prefix.rstrip()]


def render_finding(number: int, finding: Finding, t: Translator) -> list[str]:
    params = finding_params(finding, t)
    title = t(f"rules.{finding.rule_id}.title", **params)
    severity = severity_label(finding.severity, t)
    location = finding.location
    where = safe_text(str(location.path))
    if location.line is not None:
        where += ", " + t("scan.line", line=location.line)
    if location.pointer:
        where += f" ({safe_text(location.pointer, PARAM_WIDTH)})"
    if params.get("kind") == "skill":
        where += " — " + t("skills.field", tool=params["tool"], field=params.get("field", ""))
    elif params.get("tool") and params.get("field"):
        where += " — " + t("scan.tool_field", tool=params["tool"], field=params["field"])
    elif params.get("tool"):
        where += " — " + t("scan.tool_only", tool=params["tool"])
    lines = [f"  {number}. {severity} · {finding.rule_id} · {title}"]
    lines.extend(_wrapped(t("scan.where"), where))
    if finding.evidence:
        lines.extend(_wrapped(t("scan.found"), safe_text(finding.evidence, PARAM_WIDTH)))
    lines.extend(_wrapped(t("scan.why"), t(f"rules.{finding.rule_id}.why", **params)))
    lines.extend(_wrapped(t("scan.fix"), t(f"rules.{finding.rule_id}.fix", **params)))
    return lines


def _server_header(report: ServerReport, t: Translator) -> str:
    server = report.server
    risk = UNKNOWN_RISK if report.incomplete else severity_label(report.risk, t)
    label = _source_label(server.source.client.value, server.source.scope.value, t)
    return f"[{risk}] {safe_text(server.name, NAME_WIDTH)} — {label}"


def _origin_kinds(report: ServerReport, t: Translator) -> str:
    if report.tools is None:
        return ""
    kinds = sorted({origin.split(":", 1)[0] for origin in report.tools.origins})
    return ", ".join(t(f"origin.{kind}") for kind in kinds)


def coverage_line(report: ServerReport, t: Translator) -> str | None:
    collection = report.tools
    if collection is None:
        return None
    if collection.analyzed:
        line = t("scan.tools_found", count=len(collection.tools), origins=_origin_kinds(report, t))
        if collection.capabilities:
            names = ", ".join(t(f"capability.{kind.value}") for kind in collection.capabilities)
            line += " · " + t("scan.capabilities", names=names)
        return line
    gap = collection.gap.value if collection.gap is not None else "not_found"
    return t(f"gap.{gap}")


def coverage_summary(report: ScanReport, t: Translator) -> list[str]:
    if not report.tools_analyzed:
        return [t("scan.tools_skipped")]
    seen: set[int] = set()
    analyzed_servers = 0
    tool_count = 0
    gaps: dict[str, int] = {}
    for server_report in report.servers:
        collection = server_report.tools
        if collection is None or id(collection) in seen:
            continue
        seen.add(id(collection))
        if collection.analyzed:
            analyzed_servers += 1
            tool_count += len(collection.tools)
        else:
            gap = collection.gap.value if collection.gap is not None else "not_found"
            gaps[gap] = gaps.get(gap, 0) + 1
    lines = [t("scan.coverage", servers=analyzed_servers, tools=tool_count)]
    if gaps:
        parts = ", ".join(f"{t('gap_short.' + gap)} {count}" for gap, count in sorted(gaps.items()))
        lines.extend(textwrap.wrap(t("scan.coverage_gaps", parts=parts), WRAP_WIDTH))
    return lines


def ledger_line(report: ScanReport, t: Translator) -> str | None:
    ledger = report.ledger
    if ledger is None:
        return None
    key = (
        "ledger.tampered"
        if ledger.tampered
        else "ledger.ok"
        if ledger.intact
        else "ledger.unverified"
    )
    return t(key, records=ledger.records, anchor=ledger.anchor, path=safe_text(ledger.path))


def baseline_line(report: ScanReport, t: Translator) -> str | None:
    baseline = report.baseline
    if baseline is None:
        return None
    if baseline.path is None:
        return t("baseline.disabled")
    return t(f"baseline.{baseline.status}", path=safe_text(baseline.path))


def render_scan(report: ScanReport, t: Translator) -> str:
    lines = [
        t("app.banner", version=__version__),
        t("scan.title"),
        *textwrap.wrap(
            t("scan.scope_note_tools" if report.tools_analyzed else "scan.scope_note"), WRAP_WIDTH
        ),
        "",
    ]
    if not report.servers and not report.file_findings:
        lines.extend([t("scan.no_servers"), "", t("inventory.read_only")])
        return "\n".join(lines) + "\n"
    lines.append(t("scan.summary", servers=len(report.servers), findings=len(report.findings)))
    counts = report.counts()
    lines.append(
        " · ".join(
            f"{severity_label(severity, t)} {counts[severity]}"
            for severity in sorted(Severity, reverse=True)
        )
    )
    lines.append("")
    clean: list[str] = []
    for server_report in report.servers:
        if not server_report.findings and not server_report.incomplete:
            clean.append(safe_text(server_report.server.name, NAME_WIDTH))
            continue
        lines.append(_server_header(server_report, t))
        coverage = coverage_line(server_report, t)
        if coverage:
            lines.append(f"  {coverage}")
        for number, finding in enumerate(server_report.findings, start=1):
            lines.extend(render_finding(number, finding, t))
        lines.append("")
    if report.file_findings:
        lines.append(t("scan.file_problems"))
        for number, finding in enumerate(report.file_findings, start=1):
            lines.extend(render_finding(number, finding, t))
        lines.append("")
    if clean:
        unique = sorted(set(clean), key=str.lower)
        text = t("scan.clean", count=len(clean), names=", ".join(unique))
        lines.extend(textwrap.wrap(text, WRAP_WIDTH))
    lines.extend(coverage_summary(report, t))
    for extra in (baseline_line(report, t), ledger_line(report, t)):
        if extra:
            lines.extend(textwrap.wrap(extra, WRAP_WIDTH))
    if report.errors:
        lines.append(t("scan.incomplete", count=len(report.errors)))
    lines.extend(textwrap.wrap(t("scan.not_safe"), WRAP_WIDTH))
    lines.append(t("inventory.read_only"))
    return "\n".join(lines) + "\n"
