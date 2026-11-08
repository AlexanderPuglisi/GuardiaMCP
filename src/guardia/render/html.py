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
    finding_evidence,
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
  --bg: #0b0d10; --surface: #14171c; --surface-2: #0f1216; --line: #262b33; --line-soft: #1d2128;
  --text: #e9ecf0; --muted: #8a919c; --accent: #6ea9c9; --accent-soft: rgba(110, 169, 201, .12);
  --critical: #e5555a; --high: #e4883f; --medium: #dcbb4a; --low: #6f93a8; --info: #7d8590;
  --sans: "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, sans-serif;
  --mono: "Cascadia Mono", "Cascadia Code", Consolas, ui-monospace, monospace;
  color-scheme: dark;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f2f4f6; --surface: #ffffff; --surface-2: #f6f8fa; --line: #d5dae1; --line-soft: #e4e8ed;
    --text: #14181d; --muted: #5d646d; --accent: #2f7b9e; --accent-soft: rgba(47, 123, 158, .1);
    --critical: #c93338; --high: #b8692a; --medium: #9a7d16; --low: #4a6b7e; --info: #6b7280;
    color-scheme: light;
  }
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.6 var(--sans); }
main { max-width: 1040px; margin: 0 auto; padding: 36px 18px 64px; }
header { display: flex; gap: 16px; align-items: flex-start; border-bottom: 1px solid var(--line);
  padding-bottom: 22px; margin-bottom: 26px; }
.mark { width: 44px; height: 44px; flex: none; color: var(--accent); }
.mark path { fill: none; stroke: currentColor; stroke-width: 1.6; stroke-linecap: round;
  stroke-linejoin: round; }
.head { flex: 1; min-width: 0; }
h1 { font-size: 26px; margin: 0; letter-spacing: -.2px; font-weight: 600; overflow-wrap: anywhere; }
h1 span { color: var(--accent); }
.signature { color: var(--muted); font-size: 13px; margin-top: 4px; }
.meta { color: var(--muted); font-size: 13px; margin-top: 8px; }
.offline { display: inline-flex; align-items: center; gap: 8px; margin-top: 14px; padding: 5px 12px;
  border-radius: 999px; border: 1px solid var(--accent); background: var(--accent-soft);
  color: var(--accent); font: 600 12px/1.4 var(--mono); letter-spacing: .3px; }
.offline::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
h2 { font-size: 18px; font-weight: 600; margin: 34px 0 12px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; }
.card { position: relative; overflow: hidden; background: var(--surface); border: 1px solid var(--line);
  border-radius: 12px; padding: 14px 16px 14px 19px; }
.card::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--line); }
.card b { display: block; margin-top: 6px; font: 600 26px/1.1 var(--mono);
  font-variant-numeric: tabular-nums; }
.card small { color: var(--muted); text-transform: uppercase; letter-spacing: .8px; font-size: 11px; }
.card.critical::before { background: var(--critical); } .card.critical b { color: var(--critical); }
.card.high::before { background: var(--high); } .card.high b { color: var(--high); }
.card.medium::before { background: var(--medium); } .card.medium b { color: var(--medium); }
.card.low::before { background: var(--low); } .card.low b { color: var(--low); }
.card.info::before { background: var(--info); } .card.info b { color: var(--info); }
.card.zero::before { background: var(--line); } .card.zero b { color: var(--muted); }
.note { color: var(--muted); font-size: 13px; }
.entry { background: var(--surface); border: 1px solid var(--line); border-left: 3px solid var(--line);
  border-radius: 12px; margin: 12px 0; overflow: hidden; }
.entry.critical { border-left-color: var(--critical); } .entry.high { border-left-color: var(--high); }
.entry.medium { border-left-color: var(--medium); } .entry.low { border-left-color: var(--low); }
.entry.info { border-left-color: var(--info); }
summary { cursor: pointer; padding: 13px 18px; list-style: none; display: flex; gap: 10px;
  align-items: baseline; flex-wrap: wrap; }
summary::-webkit-details-marker { display: none; }
summary::after { content: "+"; margin-left: auto; color: var(--muted); font: 600 16px/1 var(--mono); }
details[open] > summary::after { content: "\\2013"; }
summary:hover .name { color: var(--accent); }
summary .name { font-weight: 600; overflow-wrap: anywhere; }
summary .where { color: var(--muted); font-size: 13px; overflow-wrap: anywhere; min-width: 0; }
code, .mono, .note, .coverage { overflow-wrap: anywhere; }
.badge { border-radius: 999px; padding: 1px 9px; font-size: 11px; font-weight: 700; letter-spacing: .5px;
  border: 1px solid currentColor; white-space: nowrap; }
.badge.critical { color: var(--critical); } .badge.high { color: var(--high); }
.badge.medium { color: var(--medium); } .badge.low { color: var(--low); }
.badge.info { color: var(--info); } .badge.none { color: var(--muted); }
.coverage { color: var(--muted); font-size: 13px; padding: 0 18px 10px; }
.finding { border-top: 1px solid var(--line-soft); padding: 14px 18px; background: var(--surface-2); }
.finding h3 { font-size: 15px; font-weight: 600; margin: 0 0 8px; display: flex; gap: 8px;
  align-items: baseline; flex-wrap: wrap; }
.finding h3 code { color: var(--muted); font-weight: 400; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 0; font-size: 14px; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
dd code { display: inline-block; max-width: 100%; padding: 2px 8px; border-radius: 6px;
  border: 1px solid var(--line); background: var(--bg); }
code, .mono { font-family: var(--mono); font-size: 13px; }
footer { margin-top: 40px; border-top: 1px solid var(--line); padding-top: 16px; color: var(--muted);
  font-size: 13px; }
@media (max-width: 560px) {
  header { flex-direction: column; gap: 12px; }
  dl { grid-template-columns: 1fr; } dt { margin-top: 6px; }
}
@media print {
  :root { --bg: #fff; --surface: #fff; --surface-2: #fafafa; --line: #ddd; --line-soft: #eee;
    --text: #111; --muted: #555; --accent: #2f7b9e; --accent-soft: transparent; }
  summary::after { content: none; }
  details { break-inside: avoid; } details:not([open]) > *:not(summary) { display: block; }
}
"""
SHIELD_MARK = (
    '<svg class="mark" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M12 2.4 20 5.2V11c0 4.6-3.4 8.3-8 10.6C7.4 19.3 4 15.6 4 11V5.2z"/>'
    '<path d="m8.2 11.7 2.7 2.7 4.9-5.6"/></svg>'
)


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
    evidence = finding_evidence(finding, t)
    if evidence:
        rows.append((t("scan.found"), f"<code>{_e(evidence, PARAM_WIDTH)}</code>"))
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
        f'<div class="card {s.label}{" zero" if not counts[s] else ""}">'
        f"<small>{_e(severity_label(s, t))}</small><b>{counts[s]}</b></div>"
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
        f'<header>{SHIELD_MARK}<div class="head"><h1>Guardia <span>MCP</span> — {_e(title)}</h1>'
        f'<div class="signature">by Alexander Puglisi · v{_e(__version__)}</div>'
        f'<div class="meta">{_e(t("html.generated", time=report.generated_at.isoformat(timespec="seconds")))}</div>'
        f'<div class="offline">{_e(t("html.offline"))}</div></div>'
        f"</header>{''.join(sections)}"
        f"<footer>{_e(t('scan.not_safe'))}<br>{_e(t('inventory.read_only'))}</footer>"
        "</main></body></html>\n"
    )
