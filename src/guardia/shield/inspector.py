from __future__ import annotations

import json
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.model import canonical_json, sha256_hex
from guardia.redact import REDACTED, SECRET_VALUE
from guardia.secure_store import KeyStoreError
from guardia.shield.confirm import Answer, Confirmer, ConfirmRequest, readable
from guardia.shield.engine import (
    Context,
    Engine,
    Evaluation,
    argument_leaf_hit,
    content_leaf_hit,
    redact,
)
from guardia.shield.messages import Direction, Message, MessageKind
from guardia.shield.patterns import MAX_WALK_DEPTH, Leaf, leaves
from guardia.shield.pins import PinError, PinStore, ToolStatus
from guardia.shield.policy import Policy, PolicyState
from guardia.shield.protections import (
    CREDENTIAL,
    PIN_ACRONYM,
    credential_request,
    elicitations,
    has_secret,
    input_elicitations,
    instructions_findings,
    over_threshold,
    redact_secrets,
    result_findings,
    rule_ids,
    tool_findings,
    tool_fingerprint,
)
from guardia.shield.proxy import CANCELLED, FORWARD, Decision, Report, Verdict
from guardia.shield.rules import Action, Phase, Protections, ResultMode, RuleSet, Sensitivity
from guardia.shield.session import Pending

TOOL_METHODS = frozenset({"tools/call", "prompts/get"})
LOGGED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
INSTRUCTION_METHODS = frozenset({"initialize", "server/discover"})
MAX_LOGGED_NAMES = 50
REMEMBER_SECONDS = 600
MAX_DETAILS = 2000
MAX_VALUE = 300
MAX_WALKED = 400
TURN_SECONDS = 0.2
ALLOWED_ANSWERS = frozenset({Answer.ALLOW, Answer.ALLOW_REMEMBER})
MAX_REPORTED_NAMES = 10
NAME_WIDTH = 120
INPUT_REQUIRED = "input_required"
LIST_CHANGED = "notifications/tools/list_changed"

PolicySource = Callable[[], Policy]
Transform = Callable[[Any], Any]
Notify = Callable[[Message], bool]
State = tuple[PolicyState, str]
Field = tuple[tuple[str, ...], str]


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _name(value: object) -> str:
    return safe_text(value, NAME_WIDTH) if isinstance(value, str) else ""


def _without_instructions(result: Any) -> Any:
    if isinstance(result, dict):
        return {key: value for key, value in result.items() if key != "instructions"}
    return result


def _fields(value: Any) -> list[Field]:
    found: list[Field] = []
    stack: list[tuple[Any, tuple[str, ...], int]] = [(value, (), 0)]
    while stack and len(found) < MAX_WALKED:
        current, keys, depth = stack.pop()
        if isinstance(current, dict | list) and depth >= MAX_WALK_DEPTH:
            found.append((keys, "…"))
        elif isinstance(current, dict):
            items = list(current.items())[:MAX_WALKED]
            stack.extend((item, (*keys, str(key)), depth + 1) for key, item in reversed(items))
        elif isinstance(current, list):
            stack.extend((item, keys, depth + 1) for item in reversed(current[:MAX_WALKED]))
        elif isinstance(current, str):
            found.append((keys, current))
        else:
            found.append((keys, json.dumps(current, ensure_ascii=False)))
    return found


def _field_block(keys: tuple[str, ...], text: str) -> str:
    shown = SECRET_VALUE.sub(REDACTED, text)
    if len(shown) > MAX_VALUE:
        shown = shown[: MAX_VALUE - 1] + "…"
    first, *rest = readable(shown).split("\n")
    label = ".".join(safe_text(key, NAME_WIDTH) for key in keys)
    head = f"{label}: {first}" if label else first
    return "\n".join([head, *(f"  {line}" for line in rest)])


def _list_changed() -> Message:
    return Message(
        MessageKind.NOTIFICATION, {"jsonrpc": "2.0", "method": LIST_CHANGED}, None, LIST_CHANGED
    )


def _declares_list_changed(result: Any) -> bool:
    capabilities = result.get("capabilities") if isinstance(result, dict) else None
    tools = capabilities.get("tools") if isinstance(capabilities, dict) else None
    return isinstance(tools, dict) and tools.get("listChanged") is True


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
        canaries: frozenset[str] = frozenset(),
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
        self._canaries = canaries
        self._engine: Engine | None = None
        self._last_state: State | None = None
        self._known: dict[str, str | None] = {}
        self._definitions: dict[str, dict[str, Any]] = {}
        self._checked: dict[str, State | None] = {}
        self._continuing = False
        self._approved_tools = True
        self._notify: Notify | None = None
        self._list_changed = False
        self._lock = threading.Lock()
        self._asking = threading.Lock()

    def attach(self, notify: Notify) -> None:
        self._notify = notify

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
        changed = False
        with self._lock:
            state = (policy.state, ruleset.sha256)
            if self._engine is None or self._last_state != state:
                changed = self._last_state is not None
                self._engine = Engine(ruleset, self._home)
                self._last_state = state
            engine = self._engine
            announce = changed and self._list_changed and bool(self._known)
        if changed:
            self._report(self.describe())
        if announce and self._notify is not None:
            self._notify(_list_changed())
        return engine, ruleset.protections

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
            checks = self._call_checks(engine, context, protections)
            return self._judge(engine, context, message, checks)
        if message.kind is MessageKind.REQUEST:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                message.method or "",
                content=message.params,
                size=len(message.encode()),
            )
            requests = elicitations(context.method, message.params)
            checks = self._request_checks(protections, requests)
            return self._judge(engine, context, message, checks)
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
        if method in INSTRUCTION_METHODS and isinstance(result, dict):
            self._list_changed = _declares_list_changed(result)
        if isinstance(result, dict) and result.get("resultType") == INPUT_REQUIRED:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                method,
                tool,
                content=result.get("inputRequests"),
                size=size,
            )
            requests = input_elicitations(result.get("inputRequests"))
            checks = self._request_checks(protections, requests)
            return self._judge(engine, context, message, checks)
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

    def _canary_hit(self, value: Any) -> str | None:
        if not self._canaries:
            return None
        for leaf in leaves(value):
            for token in self._canaries:
                if token in leaf.text:
                    return token
        return None

    def _call_checks(
        self, engine: Engine, context: Context, protections: Protections
    ) -> list[Check]:
        found: list[Check] = []
        if self._canary_hit(context.arguments) is not None:
            found.append(
                Check(
                    Action.BLOCK,
                    "canary",
                    self._t(
                        "shield.canary_outgoing",
                        server=self._server,
                        tool=context.tool or "-",
                    ),
                )
            )
        reason = (
            self._call_block_reason(engine, protections, context.tool)
            if context.method == "tools/call"
            else None
        )
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

    def _call_block_reason(self, engine: Engine, protections: Protections, tool: str) -> str | None:
        with self._lock:
            known = tool in self._known
            reason = self._known.get(tool)
            definition = self._definitions.get(tool)
            stale = self._checked.get(tool) != self._last_state
        if known and (reason is not None or not stale or definition is None):
            return reason
        if known and definition is not None:
            reason = self._list_reason(engine, protections, tool, definition)
            with self._lock:
                if tool in self._known:
                    self._known[tool] = reason
                    self._checked[tool] = self._last_state
            return reason
        if self._pins is None or not self._approved_tools:
            return None
        try:
            return self._pins.lookup(self._server, tool)
        except (OSError, KeyStoreError, PinError) as exc:
            self._report(self._t("shield.pins_failed", error=safe_text(str(exc), 200)))
            return "unavailable"

    def _list_context(self, name: str, tool: dict[str, Any]) -> Context:
        return Context(
            Phase.LIST,
            self._server,
            "tools/list",
            name,
            content=tool,
            size=len(canonical_json(tool)),
        )

    def _list_reason(
        self, engine: Engine, protections: Protections, name: str, tool: dict[str, Any]
    ) -> str | None:
        if engine.evaluate(self._list_context(name, tool), record=False).action is Action.BLOCK:
            return "rule"
        if over_threshold(tool_findings(self._server, tool), protections.analysis):
            return "analysis"
        return None

    def _request_checks(self, protections: Protections, requests: list[Any]) -> list[Check]:
        if protections.credential_requests is None:
            return []
        keyword = next(
            (found for params in requests if (found := credential_request(params)) is not None),
            None,
        )
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
        if self._canary_hit(context.content) is not None:
            found.append(
                Check(
                    Action.BLOCK,
                    "canary",
                    self._t(
                        "shield.canary_triggered",
                        server=self._server,
                        tool=context.tool or "-",
                    ),
                    note=self._t("shield.canary_note", server=self._server),
                )
            )
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
        counts = Counter(_name(tool.get("name")) for tool in tools)
        for tool in tools:
            name = _name(tool.get("name"))
            evaluation = engine.evaluate(self._list_context(name, tool))
            labels.update(evaluation.names)
            noteworthy = noteworthy or evaluation.action is not Action.ALLOW
            if evaluation.action is Action.BLOCK:
                hidden[name] = "rule"
                continue
            risky = over_threshold(tool_findings(self._server, tool), protections.analysis)
            if risky:
                hidden[name] = "analysis"
                labels.update(f"protection:analysis:{rule}" for rule in rule_ids(risky))
        for name, count in counts.items():
            if count > 1:
                hidden.setdefault(name, "duplicate")
                labels.add("protection:duplicate_tool")
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
        groups: dict[str, list[str]] = defaultdict(list)
        for tool in tools:
            groups[_name(tool.get("name"))].append(tool_fingerprint(tool))
        fingerprints = {
            name: found[0] if len(found) == 1 else sha256_hex(canonical_json(sorted(found)))
            for name, found in groups.items()
        }
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
                self._definitions[name] = tool
                self._checked[name] = self._last_state

    def _judge(
        self, engine: Engine, context: Context, message: Message, findings: list[Check]
    ) -> Decision:
        verdicts = Verdicts(engine.evaluate(context), findings)
        action = verdicts.action
        if action is Action.ASK:
            return Decision(
                Verdict.DEFER,
                reason="ask",
                resolve=lambda cancelled: self._ask(context, message, verdicts, cancelled),
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

    def _matcher(self, verdicts: Verdicts) -> Callable[[Leaf], bool]:
        asking = [rule for rule in verdicts.evaluation.rules if rule.action is Action.ASK]
        arguments = [rule.argument for rule in asking if rule.argument is not None]
        contents = [rule.content for rule in asking if rule.content is not None]
        labels = {check.label for check in verdicts.findings if check.action is Action.ASK}
        secrets = "protection:outgoing_secrets" in labels
        credentials = "protection:credential_requests" in labels

        def matched(leaf: Leaf) -> bool:
            return (
                (secrets and bool(SECRET_VALUE.search(leaf.text)))
                or (
                    credentials
                    and bool(CREDENTIAL.search(leaf.text) or PIN_ACRONYM.search(leaf.text))
                )
                or any(argument_leaf_hit(condition, leaf, self._home) for condition in arguments)
                or any(content_leaf_hit(condition, leaf) for condition in contents)
            )

        return matched

    def _details(self, value: Any, verdicts: Verdicts) -> str:
        fields = _fields(value)
        matched = self._matcher(verdicts)
        flags = [matched(Leaf(keys, text)) for keys, text in fields]
        ordered = [field for field, flag in zip(fields, flags, strict=True) if flag] + [
            field for field, flag in zip(fields, flags, strict=True) if not flag
        ]
        blocks: list[str] = []
        size = 0
        for index, (keys, text) in enumerate(ordered):
            block = _field_block(keys, text)
            if blocks and size + len(block) > MAX_DETAILS:
                blocks.append(self._t("shield.details_more", count=len(ordered) - index))
                break
            blocks.append(block)
            size += len(block) + 1
        return "\n".join(blocks)

    def _confirmation(
        self, context: Context, verdicts: Verdicts, cancelled: threading.Event | None = None
    ) -> ConfirmRequest:
        reasons = [
            self._t("shield.reason_rule", name=rule.name)
            for rule in verdicts.evaluation.rules
            if rule.action is Action.ASK
        ]
        if verdicts.evaluation.defaulted and verdicts.evaluation.action is Action.ASK:
            reasons.append(self._t("shield.by_default"))
        reasons += [check.explanation for check in verdicts.findings if check.action is Action.ASK]
        value = context.arguments if context.phase is Phase.CALL else context.content
        details = self._details(value, verdicts) if value else ""
        return ConfirmRequest(
            server=self._server,
            method=safe_text(context.method, NAME_WIDTH),
            tool=context.tool,
            reasons=tuple(safe_text(reason, 400) for reason in reasons[:8]),
            details=readable(details, MAX_DETAILS),
            language=self._t.language,
            cancelled=cancelled,
        )

    def _take_turn(self, cancelled: threading.Event) -> bool:
        while not self._asking.acquire(timeout=TURN_SECONDS):
            if cancelled.is_set():
                return False
        if cancelled.is_set():
            self._asking.release()
            return False
        return True

    def _answer(
        self,
        context: Context,
        verdicts: Verdicts,
        cancelled: threading.Event,
        key: tuple[str, tuple[str, ...]],
    ) -> tuple[Answer, bool]:
        if not self._take_turn(cancelled):
            return Answer.CANCELLED, False
        try:
            with self._lock:
                remembered = self._remembered.get(key, 0.0) > time.monotonic()
            if remembered:
                answer = Answer.ALLOW
            elif self._confirm is None:
                answer = Answer.UNAVAILABLE
            else:
                answer = self._confirm(self._confirmation(context, verdicts, cancelled))
            if answer is Answer.ALLOW_REMEMBER:
                with self._lock:
                    self._remembered[key] = time.monotonic() + REMEMBER_SECONDS
        finally:
            self._asking.release()
        if cancelled.is_set():
            return Answer.CANCELLED, False
        return answer, remembered

    def _ask(
        self, context: Context, message: Message, verdicts: Verdicts, cancelled: threading.Event
    ) -> Decision:
        key = (context.tool or context.method, tuple(sorted(verdicts.labels)))
        answer, remembered = self._answer(context, verdicts, cancelled, key)
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
        label = "remembered" if remembered else answer.value
        self._report(
            self._t(
                "shield.confirmation",
                server=self._server,
                tool=context.tool or context.method,
                answer=self._t(f"shield.answer_{label}"),
            )
        )
        if answer is Answer.CANCELLED:
            return CANCELLED
        if answer in ALLOWED_ANSWERS:
            return self._allowed(context, message, verdicts)
        explanation = f"{self._explain(verdicts)} {self._t(f'shield.ask_{answer.value}')}"
        return Decision(Verdict.REJECT, reason="ask", explanation=explanation)

    def _explain(self, verdicts: Verdicts) -> str:
        finding = verdicts.strongest_finding()
        if finding is not None:
            return finding.explanation
        names = ", ".join(
            self._t("shield.rule_name", name=name) for name in verdicts.evaluation.names[:5]
        )
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
