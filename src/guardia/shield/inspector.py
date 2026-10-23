from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.model import canonical_json, sha256_hex
from guardia.secure_store import KeyStoreError
from guardia.shield.confirm import Answer, Confirmer, ConfirmRequest
from guardia.shield.engine import Context, Engine, Evaluation, redact
from guardia.shield.messages import Direction, Message, MessageKind
from guardia.shield.pins import PinError, PinStore, ToolStatus
from guardia.shield.policy import Policy, PolicyState
from guardia.shield.protections import (
    credential_request,
    has_secret,
    instructions_findings,
    over_threshold,
    redact_secrets,
    result_findings,
    rule_ids,
    tool_findings,
    tool_fingerprint,
)
from guardia.shield.proxy import FORWARD, Decision, Report, Verdict
from guardia.shield.rules import Action, Phase, Protections, ResultMode, RuleSet, Sensitivity
from guardia.shield.session import Pending

TOOL_METHODS = frozenset({"tools/call", "prompts/get"})
LOGGED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
INSTRUCTION_METHODS = frozenset({"initialize", "server/discover"})
MAX_LOGGED_NAMES = 50
REMEMBER_SECONDS = 600
MAX_DETAILS = 2000
ALLOWED_ANSWERS = frozenset({Answer.ALLOW, Answer.ALLOW_REMEMBER})
MAX_REPORTED_NAMES = 10
NAME_WIDTH = 120
INPUT_REQUIRED = "input_required"

PolicySource = Callable[[], Policy]
Transform = Callable[[Any], Any]


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _name(value: object) -> str:
    return safe_text(value, NAME_WIDTH) if isinstance(value, str) else ""


def _without_instructions(result: Any) -> Any:
    if isinstance(result, dict):
        return {key: value for key, value in result.items() if key != "instructions"}
    return result


@dataclass(frozen=True, slots=True)
class Check:
    action: Action
    label: str
    explanation: str = ""
    transform: Transform | None = None
    note: str = ""


@dataclass(slots=True)
class Verdicts:
    evaluation: Evaluation
    findings: list[Check] = field(default_factory=list)

    @property
    def action(self) -> Action:
        actions = [self.evaluation.action, *(finding.action for finding in self.findings)]
        return max(actions, key=lambda action: action.strength)

    @property
    def labels(self) -> list[str]:
        return [*self.evaluation.names, *(finding.label for finding in self.findings)]

    def strongest_finding(self) -> Check | None:
        candidates = [
            f for f in self.findings if f.action.strength > self.evaluation.action.strength
        ]
        return max(candidates, key=lambda f: f.action.strength) if candidates else None


class RulesInspector:
    def __init__(
        self,
        *,
        server: str,
        policy: PolicySource,
        home: str,
        ledger: Ledger | None,
        t: Translator,
        report: Report,
        pins: PinStore | None = None,
        confirm: Confirmer | None = None,
    ) -> None:
        self._server = server
        self._confirm = confirm
        self._remembered: dict[tuple[str, tuple[str, ...]], float] = {}
        self._policy = policy
        self._home = home
        self._ledger = ledger
        self._t = t
        self._report = report
        self._pins = pins
        self._engine: Engine | None = None
        self._last_state: tuple[PolicyState, str] | None = None
        self._known: dict[str, str | None] = {}
        self._continuing = False
        self._approved_tools = True
        self._lock = threading.Lock()

    def describe(self) -> str:
        policy = self._policy()
        if policy.state is PolicyState.LOCKED and policy.reason is not None:
            return self._t(
                "shield.state_locked", reason=self._t(f"shield.locked_{policy.reason.value}")
            )
        if policy.state is PolicyState.ACTIVE and policy.ruleset is not None:
            return self._t(
                "shield.state_active",
                count=len(policy.ruleset.rules),
                default=self._t(f"shield_rules.action_{policy.ruleset.default.value}"),
            )
        return self._t("shield.state_none")

    def _current(self, policy: Policy) -> tuple[Engine, Protections]:
        ruleset = policy.ruleset or RuleSet()
        self._approved_tools = ruleset.protections.approved_tools
        with self._lock:
            state = (policy.state, ruleset.sha256)
            if self._engine is None or self._last_state != state:
                if self._last_state is not None:
                    self._report(self.describe())
                self._engine = Engine(ruleset, self._home)
                self._last_state = state
            return self._engine, ruleset.protections

    def inspect(self, direction: Direction, message: Message, pending: Pending | None) -> Decision:
        policy = self._policy()
        engine, protections = self._current(policy)
        if policy.state is PolicyState.LOCKED and policy.reason is not None:
            explanation = self._t(f"shield.locked_{policy.reason.value}")
            verdict = Verdict.DROP if message.kind is MessageKind.NOTIFICATION else Verdict.REJECT
            return Decision(verdict, reason="locked", explanation=explanation)
        if direction is Direction.TO_SERVER:
            if message.kind is not MessageKind.REQUEST:
                return FORWARD
            context = self._call_context(message)
            return self._judge(engine, context, message, self._call_checks(context, protections))
        if message.kind is MessageKind.REQUEST:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                message.method or "",
                content=message.params,
                size=len(message.encode()),
            )
            return self._judge(engine, context, message, self._request_checks(context, protections))
        if message.kind is MessageKind.RESPONSE:
            return self._response(engine, protections, message, pending)
        return FORWARD

    def _call_context(self, message: Message) -> Context:
        method = message.method or ""
        params = message.params
        tools = method in TOOL_METHODS
        arguments = params.get("arguments") if tools else params
        return Context(
            Phase.CALL,
            self._server,
            method,
            _name(params.get("name")) if tools else "",
            arguments,
            arguments,
            len(message.encode()),
        )

    def _response(
        self, engine: Engine, protections: Protections, message: Message, pending: Pending | None
    ) -> Decision:
        method = pending.method if pending else ""
        tool = pending.params_name if pending else ""
        result = message.payload.get("result")
        size = len(message.encode())
        if isinstance(result, dict) and result.get("resultType") == INPUT_REQUIRED:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                method,
                tool,
                content=result.get("inputRequests"),
                size=size,
            )
            return self._judge(engine, context, message, self._request_checks(context, protections))
        if (
            method == "tools/list"
            and isinstance(result, dict)
            and isinstance(result.get("tools"), list)
        ):
            return self._tool_list(engine, protections, message, result)
        content = result if "result" in message.payload else message.payload.get("error")
        context = Context(Phase.RESULT, self._server, method, tool, content=content, size=size)
        checks = self._result_checks(context, protections, result)
        return self._judge(engine, context, message, checks)

    def _call_checks(self, context: Context, protections: Protections) -> list[Check]:
        found: list[Check] = []
        reason = self._call_block_reason(context.tool) if context.method == "tools/call" else None
        if reason is not None:
            found.append(
                Check(
                    Action.BLOCK,
                    f"protection:hidden_tool:{reason}",
                    self._t(f"shield.tool_hidden_{reason}", tool=context.tool, server=self._server),
                )
            )
        if protections.outgoing_secrets is not None and has_secret(context.arguments):
            found.append(
                Check(
                    protections.outgoing_secrets,
                    "protection:outgoing_secrets",
                    self._t("shield.protection_outgoing_secrets"),
                )
            )
        return found

    def _call_block_reason(self, tool: str) -> str | None:
        with self._lock:
            if tool in self._known:
                return self._known[tool]
        if self._pins is None or not self._approved_tools:
            return None
        try:
            return self._pins.lookup(self._server, tool)
        except (OSError, KeyStoreError, PinError) as exc:
            self._report(self._t("shield.pins_failed", error=safe_text(str(exc), 200)))
            return "unavailable"

    def _request_checks(self, context: Context, protections: Protections) -> list[Check]:
        if protections.credential_requests is None:
            return []
        keyword = credential_request(context.content)
        if keyword is None:
            return []
        return [
            Check(
                protections.credential_requests,
                "protection:credential_requests",
                self._t("shield.protection_credentials", keyword=safe_text(keyword, 40)),
            )
        ]

    def _result_checks(
        self, context: Context, protections: Protections, result: Any
    ) -> list[Check]:
        found: list[Check] = []
        if (
            context.method in INSTRUCTION_METHODS
            and protections.analysis is not Sensitivity.OFF
            and isinstance(result, dict)
            and isinstance(result.get("instructions"), str)
        ):
            risky = over_threshold(
                instructions_findings(self._server, result["instructions"]), protections.analysis
            )
            if risky:
                ids = ", ".join(rule_ids(risky))
                found.append(
                    Check(
                        Action.REDACT,
                        "protection:instructions",
                        transform=_without_instructions,
                        note=self._t("shield.instructions_removed", server=self._server, rules=ids),
                    )
                )
        if protections.results is not ResultMode.OFF and context.method == "tools/call":
            injected = result_findings(self._server, context.tool, context.content)
            if injected:
                ids = ", ".join(rule_ids(injected))
                block = protections.results is ResultMode.BLOCK
                found.append(
                    Check(
                        Action.BLOCK if block else Action.LOG,
                        "protection:results",
                        self._t("shield.protection_results", rules=ids),
                        note=self._t(
                            "shield.result_warning",
                            server=self._server,
                            tool=context.tool or "-",
                            rules=ids,
                        ),
                    )
                )
        if protections.result_secrets is not None and has_secret(context.content):
            found.append(
                Check(
                    Action.REDACT,
                    "protection:result_secrets",
                    transform=redact_secrets,
                    note=self._t(
                        "shield.secrets_redacted", server=self._server, tool=context.tool or "-"
                    ),
                )
            )
        return found

    def _tool_list(
        self, engine: Engine, protections: Protections, message: Message, result: dict[str, Any]
    ) -> Decision:
        hidden: dict[str, str] = {}
        labels: set[str] = set()
        noteworthy = False
        tools = [tool for tool in result["tools"] if isinstance(tool, dict)]
        malformed = len(result["tools"]) - len(tools)
        for tool in tools:
            name = _name(tool.get("name"))
            evaluation = engine.evaluate(
                Context(
                    Phase.LIST,
                    self._server,
                    "tools/list",
                    name,
                    content=tool,
                    size=len(canonical_json(tool)),
                )
            )
            labels.update(evaluation.names)
            noteworthy = noteworthy or evaluation.action is not Action.ALLOW
            if evaluation.action is Action.BLOCK:
                hidden[name] = "rule"
                continue
            risky = over_threshold(tool_findings(self._server, tool), protections.analysis)
            if risky:
                hidden[name] = "analysis"
                labels.update(f"protection:analysis:{rule}" for rule in rule_ids(risky))
        if protections.approved_tools:
            outcome = self._review_pins(tools, result, hidden)
            if outcome is None:
                return self._pins_failure()
            for name, status in outcome.items():
                if status is not ToolStatus.APPROVED and name not in hidden:
                    hidden[name] = status.value
                    labels.add(f"protection:approved_tools:{status.value}")
        self._remember(tools, hidden)
        names = sorted(hidden)
        if (names or noteworthy or malformed) and not self._log(
            message,
            phase=Phase.LIST,
            method="tools/list",
            tool="",
            action=Action.BLOCK if names or malformed else Action.LOG,
            rules=sorted(labels),
            hidden=names[:MAX_LOGGED_NAMES],
        ):
            return self._ledger_failure()
        if not names and not malformed:
            return FORWARD
        if names:
            shown = ", ".join(names[:MAX_REPORTED_NAMES])
            self._report(self._t("shield.hidden_tools", server=self._server, tools=shown))
        payload = _copy(message.payload)
        payload["result"]["tools"] = [
            tool for tool in tools if _name(tool.get("name")) not in hidden
        ]
        return Decision(Verdict.FORWARD, Message(message.kind, payload, message.id, message.method))

    def _review_pins(
        self, tools: list[dict[str, Any]], result: dict[str, Any], hidden: dict[str, str]
    ) -> dict[str, ToolStatus] | None:
        if self._pins is None:
            return {}
        fingerprints = {_name(tool.get("name")): tool_fingerprint(tool) for tool in tools}
        try:
            review = self._pins.review(
                self._server, fingerprints, continuing=self._continuing, flags=hidden
            )
        except (OSError, KeyStoreError, PinError) as exc:
            self._report(self._t("shield.pins_failed", error=safe_text(str(exc), 200)))
            return None
        more = bool(result.get("nextCursor"))
        self._continuing = more and (review.first_use or self._continuing)
        if review.first_use:
            self._report(
                self._t("shield.tools_pinned", server=self._server, count=len(fingerprints))
            )
        if review.unverified:
            self._report(self._t("shield.pins_unverified", server=self._server))
        if review.newly_pending:
            shown = ", ".join(review.newly_pending[:MAX_REPORTED_NAMES])
            self._report(self._t("shield.tools_pending", server=self._server, tools=shown))
        return review.statuses

    def _remember(self, tools: list[dict[str, Any]], hidden: dict[str, str]) -> None:
        with self._lock:
            for tool in tools:
                name = _name(tool.get("name"))
                self._known[name] = hidden.get(name)

    def _judge(
        self, engine: Engine, context: Context, message: Message, findings: list[Check]
    ) -> Decision:
        verdicts = Verdicts(engine.evaluate(context), findings)
        action = verdicts.action
        if action is Action.ASK:
            return Decision(
                Verdict.DEFER,
                reason="ask",
                resolve=lambda: self._ask(context, message, verdicts),
            )
        logged = action is not Action.ALLOW or (
            context.phase is Phase.CALL and context.method in LOGGED_METHODS
        )
        if logged and not self._log(
            message,
            phase=context.phase,
            method=context.method,
            tool=context.tool,
            action=action,
            rules=verdicts.labels,
            defaulted=verdicts.evaluation.defaulted and not findings,
        ):
            return self._ledger_failure()
        for finding in findings:
            if finding.note:
                self._report(finding.note)
        if action is Action.BLOCK:
            self._report(
                self._t(
                    "shield.decision",
                    server=self._server,
                    action=self._t(f"shield_rules.action_{action.value}"),
                    method=context.method,
                    tool=context.tool or "-",
                    rules=", ".join(verdicts.labels) or self._t("shield.default_rule"),
                )
            )
            return Decision(
                Verdict.REJECT, reason=action.value, explanation=self._explain(verdicts)
            )
        return self._allowed(context, message, verdicts)

    def _allowed(self, context: Context, message: Message, verdicts: Verdicts) -> Decision:
        findings = verdicts.findings
        action = verdicts.action
        transforms = [finding.transform for finding in findings if finding.transform is not None]
        if action is not Action.REDACT and not transforms:
            return FORWARD
        if action is Action.REDACT and any(
            rule.action is Action.REDACT for rule in verdicts.evaluation.rules
        ):
            rules = verdicts.evaluation.rules
            transforms.insert(0, lambda value: redact(value, rules, self._home))
            self._report(
                self._t(
                    "shield.redacted",
                    server=self._server,
                    method=context.method,
                    tool=context.tool or "-",
                    rules=", ".join(verdicts.evaluation.names),
                )
            )
        return self._rewrite(message, context, transforms)

    def _rewrite(self, message: Message, context: Context, transforms: list[Transform]) -> Decision:
        payload = _copy(message.payload)

        def apply(value: Any) -> Any:
            for transform in transforms:
                value = transform(value)
            return value

        if message.kind is MessageKind.RESPONSE:
            part = "result" if "result" in payload else "error"
            payload[part] = apply(payload.get(part))
        elif context.phase is Phase.CALL and context.method in TOOL_METHODS:
            params = payload.setdefault("params", {})
            params["arguments"] = apply(params.get("arguments"))
        else:
            payload["params"] = apply(payload.get("params", {}))
        return Decision(Verdict.FORWARD, Message(message.kind, payload, message.id, message.method))

    def _confirmation(self, context: Context, verdicts: Verdicts) -> ConfirmRequest:
        reasons = [
            self._t("shield.reason_rule", name=rule.name)
            for rule in verdicts.evaluation.rules
            if rule.action is Action.ASK
        ]
        if verdicts.evaluation.defaulted and verdicts.evaluation.action is Action.ASK:
            reasons.append(self._t("shield.by_default"))
        reasons += [check.explanation for check in verdicts.findings if check.action is Action.ASK]
        value = context.arguments if context.phase is Phase.CALL else context.content
        details = json.dumps(redact_secrets(value), ensure_ascii=False, indent=2) if value else ""
        return ConfirmRequest(
            server=self._server,
            method=safe_text(context.method, NAME_WIDTH),
            tool=context.tool,
            reasons=tuple(safe_text(reason, 400) for reason in reasons[:8]),
            details=safe_text(details[:MAX_DETAILS], MAX_DETAILS),
            language=self._t.language,
        )

    def _ask(self, context: Context, message: Message, verdicts: Verdicts) -> Decision:
        key = (context.tool or context.method, tuple(sorted(verdicts.labels)))
        with self._lock:
            remembered = self._remembered.get(key, 0.0) > time.monotonic()
        if remembered:
            answer = Answer.ALLOW
        elif self._confirm is None:
            answer = Answer.UNAVAILABLE
        else:
            answer = self._confirm(self._confirmation(context, verdicts))
        if not self._log(
            message,
            phase=context.phase,
            method=context.method,
            tool=context.tool,
            action=Action.ASK,
            rules=verdicts.labels,
            answer="remembered" if remembered else answer.value,
        ):
            return self._ledger_failure()
        if answer is Answer.ALLOW_REMEMBER:
            with self._lock:
                self._remembered[key] = time.monotonic() + REMEMBER_SECONDS
        label = "remembered" if remembered else answer.value
        self._report(
            self._t(
                "shield.confirmation",
                server=self._server,
                tool=context.tool or context.method,
                answer=self._t(f"shield.answer_{label}"),
            )
        )
        if answer in ALLOWED_ANSWERS:
            return self._allowed(context, message, verdicts)
        explanation = f"{self._explain(verdicts)} {self._t(f'shield.ask_{answer.value}')}"
        return Decision(Verdict.REJECT, reason="ask", explanation=explanation)

    def _explain(self, verdicts: Verdicts) -> str:
        finding = verdicts.strongest_finding()
        if finding is not None:
            return finding.explanation
        names = ", ".join(f"«{name}»" for name in verdicts.evaluation.names[:5])
        if verdicts.evaluation.defaulted:
            return self._t("shield.by_default")
        return self._t("shield.by_rule", rules=names)

    def _log(
        self,
        message: Message,
        *,
        phase: Phase,
        method: str,
        tool: str,
        action: Action,
        rules: list[str],
        defaulted: bool = False,
        hidden: list[str] | None = None,
        answer: str | None = None,
    ) -> bool:
        if self._ledger is None:
            return True
        data: dict[str, object] = {
            "server": self._server,
            "phase": phase.value,
            "method": safe_text(method, NAME_WIDTH),
            "tool": tool,
            "action": action.value,
            "rules": [safe_text(name, NAME_WIDTH) for name in rules[:MAX_LOGGED_NAMES]],
            "defaulted": defaulted,
            "fingerprint": sha256_hex(message.encode()),
        }
        if hidden:
            data["hidden"] = hidden
        if answer is not None:
            data["answer"] = answer
        try:
            self._ledger.append("shield_decision", data)
        except (OSError, KeyStoreError) as exc:
            self._report(self._t("shield.ledger_failed_decision", error=safe_text(str(exc), 200)))
            return False
        return True

    def _ledger_failure(self) -> Decision:
        return Decision(
            Verdict.REJECT, reason="ledger", explanation=self._t("shield.ledger_unavailable")
        )

    def _pins_failure(self) -> Decision:
        return Decision(
            Verdict.REJECT, reason="pins", explanation=self._t("shield.pins_unavailable")
        )
