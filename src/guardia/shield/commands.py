from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, TextIO

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.model import Scope
from guardia.safeio import SafeReadError
from guardia.secure_store import Protector
from guardia.shield.activation import (
    ActivationStore,
    Candidate,
    Outcome,
    Support,
    editable,
    manual_snippet,
)
from guardia.shield.activation import Report as ActivationReport
from guardia.shield.engine import Context, Engine, redact
from guardia.shield.pins import PinError, PinStore
from guardia.shield.policy import (
    ApprovalError,
    PolicyState,
    approve_rules,
    approved_text,
    load_policy,
    read_rules_text,
    rules_path,
)
from guardia.shield.rules import PHASE_NAMES, Action, Issue, Phase, RuleSet, parse_rules
from guardia.shield.wrapping import LauncherState, launcher, launcher_state

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2
EXIT_FAILED = 3
MAX_DIFF_LINES = 80
MAX_PREVIEW_LINES = 200
EXAMPLES = {"it": "regole-it.toml", "en": "rules-en.toml"}
DEFAULT_METHODS = {
    Phase.CALL: "tools/call",
    Phase.RESULT: "tools/call",
    Phase.LIST: "tools/list",
    Phase.SERVER_REQUEST: "elicitation/create",
}


@dataclass(frozen=True, slots=True)
class Workspace:
    t: Translator
    directory: Path
    home: str
    out: TextIO
    protector: Protector | None = None

    def write(self, *lines: str) -> None:
        self.out.write("\n".join(lines) + "\n")

    def action(self, action: Action) -> str:
        return self.t(f"shield_rules.action_{action.value}")

    def path(self, path: Path) -> str:
        return safe_text(str(path))


@dataclass(frozen=True, slots=True)
class Simulation:
    server: str
    phase: str
    method: str | None
    tool: str
    arguments: str | None
    text: str


def example_text(language: str) -> str:
    name = EXAMPLES.get(language, EXAMPLES["en"])
    return resources.files("guardia.shield").joinpath("examples", name).read_text("utf-8")


def format_issue(issue: Issue, t: Translator) -> str:
    message = t(f"shield_rules.{issue.code}", **issue.params)
    rule = t("shield_rules.rule_part", name=safe_text(issue.rule, 80)) if issue.rule else ""
    return t(
        "shield_rules.issue",
        level=t(f"shield_rules.level_{issue.level.value}"),
        line=issue.line if issue.line is not None else "-",
        rule=rule,
        message=message,
    )


def verify(ws: Workspace, file: Path | None) -> int:
    path = file or rules_path(ws.directory)
    ws.write(ws.t("shield_rules.file", path=ws.path(path)))
    try:
        text = read_rules_text(path)
    except SafeReadError:
        ws.write(ws.t("shield_rules.missing_file", path=ws.path(path)))
        return EXIT_USAGE
    result = parse_rules(text, ws.home)
    for issue in result.issues:
        ws.write(format_issue(issue, ws.t))
    if result.ruleset is None:
        ws.write(ws.t("shield_rules.invalid", count=len(result.errors)))
        return EXIT_INVALID
    ws.write(
        ws.t(
            "shield_rules.valid",
            count=len(result.ruleset.rules),
            default=ws.action(result.ruleset.default),
        )
    )
    return EXIT_OK


def _diff(previous: str | None, current: str, t: Translator) -> list[str]:
    if previous is None:
        return [t("shield_rules.diff_none")]
    lines = list(
        difflib.unified_diff(
            previous.splitlines(), current.splitlines(), "approvate", "nuove", lineterm="", n=1
        )
    )
    if not lines:
        return [t("shield_rules.diff_same")]
    shown = [safe_text(line, 160) for line in lines[:MAX_DIFF_LINES]]
    if len(lines) > MAX_DIFF_LINES:
        shown.append(t("shield_rules.diff_more", count=len(lines) - MAX_DIFF_LINES))
    return [t("shield_rules.diff_title"), *shown]


def approve(ws: Workspace) -> int:
    path = rules_path(ws.directory)
    ws.write(ws.t("shield_rules.file", path=ws.path(path)))
    previous = approved_text(ws.directory)
    try:
        result, text = approve_rules(ws.directory, ws.home, ws.protector)
    except SafeReadError:
        ws.write(ws.t("shield_rules.missing_file", path=ws.path(path)))
        return EXIT_USAGE
    except ApprovalError as exc:
        ws.write(ws.t("shield_rules.approval_failed", error=safe_text(str(exc), 200)))
        return EXIT_FAILED
    for issue in result.issues:
        ws.write(format_issue(issue, ws.t))
    if result.ruleset is None:
        ws.write(ws.t("shield_rules.not_approved"))
        return EXIT_INVALID
    ws.write(*_diff(previous, text, ws.t))
    ws.write(
        ws.t(
            "shield_rules.approved",
            count=len(result.ruleset.rules),
            sha=result.ruleset.sha256[:16],
        )
    )
    return EXIT_OK


def status(ws: Workspace) -> int:
    policy = load_policy(ws.directory, ws.home, ws.protector)
    ws.write(ws.t("shield_rules.file", path=ws.path(rules_path(ws.directory))))
    if policy.state is PolicyState.LOCKED and policy.reason is not None:
        ws.write(ws.t("shield.state_locked", reason=ws.t(f"shield.locked_{policy.reason.value}")))
        return EXIT_INVALID
    if policy.ruleset is None:
        ws.write(ws.t("shield.state_none"))
        return EXIT_OK
    ws.write(
        ws.t(
            "shield.state_active",
            count=len(policy.ruleset.rules),
            default=ws.action(policy.ruleset.default),
        )
    )
    return EXIT_OK


def example(ws: Workspace, save: bool) -> int:
    text = example_text(ws.t.language)
    if not save:
        ws.out.write(text)
        return EXIT_OK
    path = rules_path(ws.directory)
    if path.exists():
        ws.write(ws.t("shield_rules.example_exists", path=ws.path(path)))
        return EXIT_FAILED
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    ws.write(ws.t("shield_rules.example_saved", path=ws.path(path)))
    return EXIT_OK


def _ruleset(ws: Workspace, file: Path | None) -> RuleSet | None:
    if file is not None:
        try:
            result = parse_rules(read_rules_text(file), ws.home)
        except SafeReadError:
            ws.write(ws.t("shield_rules.missing_file", path=ws.path(file)))
            return None
        for issue in result.errors:
            ws.write(format_issue(issue, ws.t))
        return result.ruleset
    policy = load_policy(ws.directory, ws.home, ws.protector)
    if policy.state is PolicyState.LOCKED and policy.reason is not None:
        ws.write(ws.t("shield.state_locked", reason=ws.t(f"shield.locked_{policy.reason.value}")))
        return None
    return policy.ruleset or RuleSet()


def _context(simulation: Simulation, phase: Phase, arguments: Any) -> Context:
    method = simulation.method or DEFAULT_METHODS[phase]
    text = simulation.text
    content: Any
    if phase is Phase.CALL:
        content = arguments
    elif phase is Phase.LIST:
        content = {"name": simulation.tool, "description": text}
    elif phase is Phase.RESULT:
        content = {"content": [{"type": "text", "text": text}]}
    else:
        content = {"message": text}
    size = len(json.dumps(content, ensure_ascii=False).encode("utf-8"))
    return Context(phase, simulation.server, method, simulation.tool, arguments, content, size)


def simulate(ws: Workspace, file: Path | None, simulation: Simulation) -> int:
    phase = PHASE_NAMES.get(simulation.phase.lower())
    if phase is None:
        ws.write(ws.t("shield_rules.bad_phase", value=safe_text(simulation.phase, 40)))
        return EXIT_USAGE
    try:
        arguments = json.loads(simulation.arguments) if simulation.arguments else {}
    except ValueError:
        arguments = None
    if not isinstance(arguments, dict):
        ws.write(ws.t("shield_rules.bad_arguments"))
        return EXIT_USAGE
    ruleset = _ruleset(ws, file)
    if ruleset is None:
        return EXIT_INVALID
    context = _context(simulation, phase, arguments)
    evaluation = Engine(ruleset, ws.home).evaluate(context, record=False)
    ws.write(ws.t("shield_rules.decision", action=ws.action(evaluation.action).upper()))
    if evaluation.defaulted:
        ws.write(ws.t("shield_rules.defaulted", action=ws.action(evaluation.action)))
    else:
        ws.write(ws.t("shield_rules.matched"))
        for rule in evaluation.rules:
            ws.write(
                ws.t(
                    "shield_rules.matched_line",
                    name=safe_text(rule.name, 120),
                    action=ws.action(rule.action),
                )
            )
    if phase is Phase.LIST and evaluation.action is Action.BLOCK:
        ws.write(ws.t("shield_rules.hidden"))
    if evaluation.action is Action.REDACT:
        target = arguments if phase is Phase.CALL else context.content
        preview = json.dumps(
            redact(target, evaluation.rules, ws.home), ensure_ascii=False, indent=2
        )
        ws.write(ws.t("shield_rules.redacted_preview"))
        for line in preview.splitlines()[:MAX_PREVIEW_LINES]:
            ws.write(safe_text(line, 400))
    return EXIT_OK


def tools_list(ws: Workspace, store: PinStore) -> int:
    ws.write(ws.t("shield_rules.tools_file", path=ws.path(store.path)))
    try:
        waiting, approved, valid = store.pending()
    except (OSError, PinError) as exc:
        ws.write(ws.t("shield_rules.tools_failed", error=safe_text(str(exc), 200)))
        return EXIT_FAILED
    if not valid:
        ws.write(ws.t("shield_rules.tools_unverified"))
        return EXIT_INVALID
    if not approved:
        ws.write(ws.t("shield_rules.tools_none"))
        return EXIT_OK
    for server, count in approved.items():
        mine = [item for item in waiting if item.server == server]
        ws.write(
            ws.t(
                "shield_rules.tools_server_line",
                server=safe_text(server, 80),
                approved=count,
                pending=len(mine),
            )
        )
        for item in mine:
            ws.write(
                ws.t(
                    "shield_rules.tools_pending_line",
                    tool=safe_text(item.name, 120),
                    reason=ws.t(f"shield_rules.reason_{item.reason.value}"),
                    seen=safe_text(item.seen, 40),
                    fingerprint=item.fingerprint[:12],
                )
            )
    return EXIT_OK


def tools_approve(ws: Workspace, store: PinStore, server: str | None, names: list[str]) -> int:
    if not server:
        ws.write(ws.t("shield_rules.tools_need_server"))
        return EXIT_USAGE
    try:
        chosen = store.approve(server, names)
    except (OSError, PinError) as exc:
        ws.write(ws.t("shield_rules.tools_failed", error=safe_text(str(exc), 200)))
        return EXIT_FAILED
    if not chosen:
        ws.write(ws.t("shield_rules.tools_nothing", server=safe_text(server, 80)))
        return EXIT_INVALID
    listed = ", ".join(safe_text(name, 120) for name in chosen)
    ws.write(ws.t("shield_rules.tools_approved", server=safe_text(server, 80), tools=listed))
    return EXIT_OK


def tools_forget(ws: Workspace, store: PinStore, server: str | None) -> int:
    if not server:
        ws.write(ws.t("shield_rules.tools_need_server"))
        return EXIT_USAGE
    try:
        forgotten = store.forget(server)
    except (OSError, PinError) as exc:
        ws.write(ws.t("shield_rules.tools_failed", error=safe_text(str(exc), 200)))
        return EXIT_FAILED
    key = "shield_rules.tools_forgotten" if forgotten else "shield_rules.tools_unknown"
    ws.write(ws.t(key, server=safe_text(server, 80)))
    return EXIT_OK if forgotten else EXIT_INVALID


def _status(ws: Workspace, candidate: Candidate) -> str:
    if candidate.support is Support.PROTECTED:
        state = launcher_state(candidate.server.shield_launcher)
        if state is not LauncherState.CURRENT:
            return ws.t(f"shield_setup.launcher_{state.value}")
    return ws.t(f"shield_setup.support_{candidate.support.value}")


def _setup_line(ws: Workspace, candidate: Candidate) -> str:
    server = candidate.server
    return ws.t(
        "shield_setup.line",
        name=safe_text(server.name, 80),
        client=ws.t(f"client.{server.source.client.value}"),
        status=_status(ws, candidate),
    )


def _rewritable(candidate: Candidate) -> bool:
    return candidate.support is Support.PROTECTED and editable(candidate.server.source.path)


def shield_list(ws: Workspace, found: list[Candidate]) -> int:
    servers = [c for c in found if c.server.source.scope is not Scope.SKILL]
    if not servers:
        ws.write(ws.t("shield_setup.no_servers"))
        return EXIT_OK
    for path in sorted({str(c.server.source.path) for c in servers}):
        ws.write(ws.t("shield_setup.file", path=safe_text(path)))
        for candidate in servers:
            if str(candidate.server.source.path) == path:
                ws.write(_setup_line(ws, candidate))
    protected = sum(1 for c in servers if c.support is Support.PROTECTED)
    ws.write(ws.t("shield_setup.summary", protected=protected, total=len(servers)))
    return EXIT_OK


def _selected(
    found: list[Candidate], names: list[str], everything: bool
) -> tuple[list[Candidate], list[str]]:
    servers = [c for c in found if c.server.source.scope is not Scope.SKILL]
    if everything:
        return servers, []
    chosen = [c for c in servers if c.server.name in names]
    missing = sorted(set(names) - {c.server.name for c in chosen})
    return chosen, missing


def _confirm_flag(ws: Workspace) -> str:
    return "--conferma" if ws.t.language == "it" else "--confirm"


def _report_changes(ws: Workspace, report: ActivationReport) -> int:
    failures = 0
    for change in report.changes:
        key = f"shield_setup.outcome_{change.outcome.value}"
        ws.write(ws.t(key, name=safe_text(change.server, 80), path=safe_text(str(change.file))))
        failures += change.outcome is not Outcome.DONE
    for backup in report.backups:
        ws.write(ws.t("shield_setup.backup", path=safe_text(str(backup))))
    return EXIT_OK if report.changes and not failures else EXIT_INVALID


def shield_enable(
    ws: Workspace,
    found: list[Candidate],
    selection: tuple[list[str], bool, bool],
    store: ActivationStore,
) -> int:
    names, everything, confirmed = selection
    if not names and not everything:
        ws.write(ws.t("shield_setup.need_selection"))
        return EXIT_USAGE
    chosen, missing = _selected(found, names, everything)
    for name in missing:
        ws.write(ws.t("shield_setup.unknown", name=safe_text(name, 80)))
    starter = launcher()
    automatic = [c for c in chosen if c.support is Support.AUTO]
    for candidate in chosen:
        if candidate.support in (Support.MANUAL_COMMENTS, Support.MANUAL_TOML):
            ws.write(_setup_line(ws, candidate))
            ws.write(ws.t("shield_setup.manual_hint"))
            ws.write(manual_snippet(candidate.server, starter))
        elif candidate.support is not Support.AUTO:
            ws.write(_setup_line(ws, candidate))
    if not automatic:
        ws.write(ws.t("shield_setup.nothing_to_do"))
        return EXIT_INVALID
    if not confirmed:
        ws.write(ws.t("shield_setup.preview_title"))
        for candidate in automatic:
            ws.write(
                ws.t(
                    "shield_setup.preview_line",
                    name=safe_text(candidate.server.name, 80),
                    path=safe_text(str(candidate.server.source.path)),
                )
            )
        ws.write(ws.t("shield_setup.preview_hint", flag=_confirm_flag(ws)))
        return EXIT_OK
    return _report_changes(ws, store.enable([c.server for c in automatic], starter))


def shield_disable(
    ws: Workspace,
    found: list[Candidate],
    store: ActivationStore,
    selection: tuple[list[str], bool, bool],
) -> int:
    names, everything, confirmed = selection
    if not names and not everything:
        ws.write(ws.t("shield_setup.need_selection"))
        return EXIT_USAGE
    chosen, _ = _selected(found, names, everything)
    protected = [c.server for c in chosen if _rewritable(c)]
    records = [r for r in store.records() if everything or r.get("server") in names]
    pending = sorted(
        {(str(r.get("server")), str(r.get("file"))) for r in records}
        | {(s.name, str(s.source.path)) for s in protected}
    )
    if not pending:
        ws.write(ws.t("shield_setup.nothing_recorded"))
        return EXIT_INVALID
    if not confirmed:
        ws.write(ws.t("shield_setup.preview_disable_title"))
        for name, path in pending:
            ws.write(
                ws.t(
                    "shield_setup.preview_line",
                    name=safe_text(name, 80),
                    path=safe_text(path),
                )
            )
        ws.write(ws.t("shield_setup.preview_hint", flag=_confirm_flag(ws)))
        return EXIT_OK
    store.adopt(protected)
    return _report_changes(ws, store.disable(None if everything else names))


def shield_relink(
    ws: Workspace,
    found: list[Candidate],
    store: ActivationStore,
    selection: tuple[list[str], bool, bool],
) -> int:
    names, everything, confirmed = selection
    if not names and not everything:
        ws.write(ws.t("shield_setup.need_selection"))
        return EXIT_USAGE
    chosen, missing = _selected(found, names, everything)
    for name in missing:
        ws.write(ws.t("shield_setup.unknown", name=safe_text(name, 80)))
    stale = [
        c
        for c in chosen
        if _rewritable(c) and launcher_state(c.server.shield_launcher) is not LauncherState.CURRENT
    ]
    if not stale:
        ws.write(ws.t("shield_setup.relink_nothing"))
        return EXIT_OK if not missing else EXIT_INVALID
    if not confirmed:
        ws.write(ws.t("shield_setup.preview_relink_title"))
        for candidate in stale:
            ws.write(_setup_line(ws, candidate))
        ws.write(ws.t("shield_setup.preview_hint", flag=_confirm_flag(ws)))
        return EXIT_OK
    return _report_changes(ws, store.relink([c.server for c in stale], launcher()))
