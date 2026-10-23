from __future__ import annotations

from html import escape

from guardia import __version__
from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.model import Finding, Severity
from guardia.render.terminal import (
    NAME_WIDTH,
    PARAM_WIDTH,
    baseline_line,
    coverage_line,
    coverage_summary,
    finding_params,
    ledger_line,
    severity_label,
)
from guardia.scanner import ScanReport, ServerReport

CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)

STYLE = """
:root {
  --bg: #08080a; --surface: #111115; --surface-2: #17171c; --line: #26262d;
  --text: #ece9e6; --muted: #9b98a0; --accent: #8e1b1b; --accent-strong: #b3261e;
  --critical: #e5484d; --high: #c4332b; --medium: #c98a2b; --low: #6f8f7a; --info: #6c7a89;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width: 1040px; margin: 0 auto; padding: 32px 16px 64px; }
header { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 24px; }
h1 { font-size: 26px; margin: 0; letter-spacing: .2px; }
h1 span { color: var(--accent-strong); }
.signature { color: var(--muted); font-size: 13px; margin-top: 4px; }
.meta { color: var(--muted); font-size: 13px; margin-top: 12px; }
h2 { font-size: 18px; margin: 32px 0 12px; color: var(--text); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.card b { display: block; font-size: 24px; }
.card small { color: var(--muted); text-transform: uppercase; letter-spacing: .6px; font-size: 11px; }
.note { color: var(--muted); font-size: 13px; }
.entry { background: var(--surface); border: 1px solid var(--line); border-left: 3px solid var(--line);
  border-radius: 10px; margin: 12px 0; }
.entry.critical, .entry.high { border-left-color: var(--accent-strong); }
.entry.medium { border-left-color: var(--medium); }
summary { cursor: pointer; padding: 12px 16px; list-style: none; display: flex; gap: 10px;
  align-items: baseline; flex-wrap: wrap; }
summary::-webkit-details-marker { display: none; }
summary .name { font-weight: 600; overflow-wrap: anywhere; }
summary .where { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; min-width: 0; }
code, .mono, .note, .coverage { overflow-wrap: anywhere; }
.badge { border-radius: 999px; padding: 1px 9px; font-size: 11px; font-weight: 700; letter-spacing: .5px;
  border: 1px solid currentColor; white-space: nowrap; }
.badge.critical { color: var(--critical); } .badge.high { color: var(--high); }
.badge.medium { color: var(--medium); } .badge.low { color: var(--low); }
.badge.info { color: var(--info); } .badge.none { color: var(--muted); }
.coverage { color: var(--muted); font-size: 13px; padding: 0 16px 8px; }
.finding { border-top: 1px solid var(--line); padding: 12px 16px; background: var(--surface-2); }
.finding h3 { font-size: 15px; margin: 0 0 6px; display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
.finding h3 code { color: var(--muted); font-weight: 400; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 0; font-size: 14px; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
code, .mono { font-family: "Cascadia Mono", Consolas, ui-monospace, monospace; font-size: 13px; }
footer { margin-top: 40px; border-top: 1px solid var(--line); padding-top: 16px; color: var(--muted); font-size: 13px; }
@media (max-width: 560px) { dl { grid-template-columns: 1fr; } dt { margin-top: 6px; } }
@media print {
  :root { --bg: #fff; --surface: #fff; --surface-2: #fafafa; --line: #ddd; --text: #111; --muted: #555; }
  details { break-inside: avoid; } details:not([open]) > *:not(summary) { display: block; }
}
"""


def _e(value: object, width: int | None = None) -> str:
    return escape(safe_text(str(value), width), quote=True)


def _badge(severity: Severity | None, t: Translator, incomplete: bool = False) -> str:
    css = "none" if severity is None else severity.label
    label = "?" if incomplete else severity_label(severity, t)
    return f'<span class="badge {css}">{_e(label)}</span>'


def _finding(finding: Finding, t: Translator) -> str:
    params = finding_params(finding, t)
    title = t(f"rules.{finding.rule_id}.title", **params)
    location = finding.location
    where = str(location.path)
    if location.line is not None:
        where += ", " + t("scan.line", line=location.line)
    if location.pointer:
        where += f" ({location.pointer})"
    if params.get("tool"):
        key = "skills.field" if params.get("kind") == "skill" else "scan.tool_field"
        where += " — " + t(key, tool=params["tool"], field=params.get("field", ""))
    rows = [(t("scan.where"), f'<span class="mono">{_e(where)}</span>')]
    if finding.evidence:
        rows.append((t("scan.found"), f"<code>{_e(finding.evidence, PARAM_WIDTH)}</code>"))
    rows.append((t("scan.why"), _e(t(f"rules.{finding.rule_id}.why", **params))))
    rows.append((t("scan.fix"), _e(t(f"rules.{finding.rule_id}.fix", **params))))
    body = "".join(f"<dt>{_e(label)}</dt><dd>{value}</dd>" for label, value in rows)
    return (
        f'<div class="finding"><h3>{_badge(finding.severity, t)}<span>{_e(title)}</span>'
        f"<code>{_e(finding.rule_id)}</code></h3><dl>{body}</dl></div>"
    )


def _entry(report: ServerReport, t: Translator) -> str:
    server = report.server
    risk = report.risk
    css = "none" if risk is None else risk.label
    label = (
        f"{t('client.' + server.source.client.value)} · {t('scope.' + server.source.scope.value)}"
    )
    coverage = coverage_line(report, t)
    opened = " open" if risk is not None and risk >= Severity.HIGH else ""
    parts = [
        f'<details class="entry {css}"{opened}><summary>{_badge(risk, t, report.incomplete)}'
        f'<span class="name">{_e(server.name, NAME_WIDTH)}</span>'
        f'<span class="where">{_e(label)} · {_e(server.source.path)}</span></summary>'
    ]
    if coverage:
        parts.append(f'<div class="coverage">{_e(coverage)}</div>')
    parts.extend(_finding(finding, t) for finding in report.findings)
    parts.append("</details>")
    return "".join(parts)


def render_html(report: ScanReport, t: Translator) -> str:
    counts = report.counts()
    cards = "".join(
        f'<div class="card"><small>{_e(severity_label(s, t))}</small><b>{counts[s]}</b></div>'
        for s in sorted(Severity, reverse=True)
    )
    flagged = [r for r in report.servers if r.findings or r.incomplete]
    clean = sorted(
        {r.server.name for r in report.servers if not r.findings and not r.incomplete},
        key=str.lower,
    )
    notes = [*coverage_summary(report, t)]
    for line in (baseline_line(report, t), ledger_line(report, t)):
        if line:
            notes.append(line)
    if report.errors:
        notes.append(t("scan.incomplete", count=len(report.errors)))
    sections = [
        f"<h2>{_e(t('scan.summary', servers=len(report.servers), findings=len(report.findings)))}</h2>",
        f'<div class="cards">{cards}</div>',
        f'<p class="note">{_e(t("scan.scope_note_tools" if report.tools_analyzed else "scan.scope_note"))}</p>',
    ]
    if flagged:
        sections.append(f"<h2>{_e(t('html.flagged'))}</h2>")
        sections.extend(_entry(entry, t) for entry in flagged)
    if report.file_findings:
        sections.append(f"<h2>{_e(t('scan.file_problems'))}</h2>")
        sections.append('<div class="entry high" style="padding-bottom:4px">')
        sections.extend(_finding(finding, t) for finding in report.file_findings)
        sections.append("</div>")
    if clean:
        sections.append(f"<h2>{_e(t('html.clean_title', count=len(clean)))}</h2>")
        sections.append(f'<p class="note">{_e(", ".join(clean))}</p>')
    sections.append(f"<h2>{_e(t('html.coverage_title'))}</h2>")
    sections.extend(f'<p class="note">{_e(line)}</p>' for line in notes)
    title = t("html.title")
    return (
        "<!doctype html>\n"
        f'<html lang="{_e(t.language)}"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{_e(title)}</title><style>{STYLE}</style></head><body><main>"
        f"<header><h1>Guardia <span>MCP</span> — {_e(title)}</h1>"
        f'<div class="signature">by Alexander Puglisi · v{_e(__version__)}</div>'
        f'<div class="meta">{_e(t("html.generated", time=report.generated_at.isoformat(timespec="seconds")))}</div>'
        f"</header>{''.join(sections)}"
        f"<footer>{_e(t('scan.not_safe'))}<br>{_e(t('inventory.read_only'))}</footer>"
        "</main></body></html>\n"
    )
