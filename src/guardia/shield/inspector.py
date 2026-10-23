from __future__ import annotations

import json
import threading
from collections.abc import Callable
from typing import Any

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.ledger import Ledger
from guardia.model import canonical_json, sha256_hex
from guardia.secure_store import KeyStoreError
from guardia.shield.engine import Context, Engine, Evaluation, redact
from guardia.shield.messages import Direction, Message, MessageKind
from guardia.shield.policy import Policy, PolicyState
from guardia.shield.proxy import FORWARD, Decision, Report, Verdict
from guardia.shield.rules import Action, Phase, RuleSet
from guardia.shield.session import Pending

TOOL_METHODS = frozenset({"tools/call", "prompts/get"})
LOGGED_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})
MAX_LOGGED_NAMES = 50
NAME_WIDTH = 120
INPUT_REQUIRED = "input_required"

PolicySource = Callable[[], Policy]


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _name(value: object) -> str:
    return safe_text(value, NAME_WIDTH) if isinstance(value, str) else ""


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
    ) -> None:
        self._server = server
        self._policy = policy
        self._home = home
        self._ledger = ledger
        self._t = t
        self._report = report
        self._engine: Engine | None = None
        self._last_state: tuple[PolicyState, str] | None = None
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

    def _current_engine(self, policy: Policy) -> Engine:
        ruleset = policy.ruleset or RuleSet()
        with self._lock:
            state = (policy.state, ruleset.sha256)
            if self._engine is None or self._last_state != state:
                if self._last_state is not None:
                    self._report(self.describe())
                self._engine = Engine(ruleset, self._home)
                self._last_state = state
            return self._engine

    def inspect(self, direction: Direction, message: Message, pending: Pending | None) -> Decision:
        policy = self._policy()
        engine = self._current_engine(policy)
        if policy.state is PolicyState.LOCKED and policy.reason is not None:
            explanation = self._t(f"shield.locked_{policy.reason.value}")
            verdict = Verdict.DROP if message.kind is MessageKind.NOTIFICATION else Verdict.REJECT
            return Decision(verdict, reason="locked", explanation=explanation)
        if direction is Direction.TO_SERVER:
            if message.kind is not MessageKind.REQUEST:
                return FORWARD
            return self._judge(engine, self._call_context(message), message, "params")
        if message.kind is MessageKind.REQUEST:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                message.method or "",
                content=message.params,
                size=len(message.encode()),
            )
            return self._judge(engine, context, message, "params")
        if message.kind is MessageKind.RESPONSE:
            return self._response(engine, message, pending)
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

    def _response(self, engine: Engine, message: Message, pending: Pending | None) -> Decision:
        method = pending.method if pending else ""
        tool = pending.params_name if pending else ""
        result = message.payload.get("result")
        if isinstance(result, dict) and result.get("resultType") == INPUT_REQUIRED:
            context = Context(
                Phase.SERVER_REQUEST,
                self._server,
                method,
                tool,
                content=result.get("inputRequests"),
                size=len(message.encode()),
            )
            return self._judge(engine, context, message, "result")
        if (
            method == "tools/list"
            and isinstance(result, dict)
            and isinstance(result.get("tools"), list)
        ):
            return self._tool_list(engine, message, result)
        content = result if "result" in message.payload else message.payload.get("error")
        context = Context(
            Phase.RESULT, self._server, method, tool, content=content, size=len(message.encode())
        )
        return self._judge(engine, context, message, "result")

    def _tool_list(self, engine: Engine, message: Message, result: dict[str, Any]) -> Decision:
        kept: list[Any] = []
        hidden: list[str] = []
        rules: set[str] = set()
        noteworthy = False
        for tool in result["tools"]:
            if not isinstance(tool, dict):
                hidden.append("?")
                continue
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
            rules.update(evaluation.names)
            noteworthy = noteworthy or evaluation.action is not Action.ALLOW
            if evaluation.action is Action.BLOCK:
                hidden.append(name)
            else:
                kept.append(tool)
        if (hidden or noteworthy) and not self._log(
            message,
            phase=Phase.LIST,
            method="tools/list",
            tool="",
            action=Action.BLOCK if hidden else Action.LOG,
            rules=sorted(rules),
            hidden=hidden[:MAX_LOGGED_NAMES],
        ):
            return self._ledger_failure()
        if not hidden:
            return FORWARD
        self._report(
            self._t("shield.hidden_tools", server=self._server, tools=", ".join(hidden[:10]))
        )
        payload = _copy(message.payload)
        payload["result"]["tools"] = kept
        return Decision(Verdict.FORWARD, Message(message.kind, payload, message.id, message.method))

    def _judge(self, engine: Engine, context: Context, message: Message, part: str) -> Decision:
        evaluation = engine.evaluate(context)
        action = evaluation.action
        logged = action is not Action.ALLOW or (
            context.phase is Phase.CALL and context.method in LOGGED_METHODS
        )
        if logged and not self._log(
            message,
            phase=context.phase,
            method=context.method,
            tool=context.tool,
            action=action,
            rules=evaluation.names,
            defaulted=evaluation.defaulted,
        ):
            return self._ledger_failure()
        if action in (Action.ALLOW, Action.LOG):
            return FORWARD
        if action is Action.REDACT:
            return self._redacted(message, evaluation, part, context)
        self._report(
            self._t(
                "shield.decision",
                server=self._server,
                action=self._t(f"shield_rules.action_{action.value}"),
                method=context.method,
                tool=context.tool or "-",
                rules=", ".join(evaluation.names) or self._t("shield.default_rule"),
            )
        )
        return Decision(Verdict.REJECT, reason=action.value, explanation=self._explain(evaluation))

    def _explain(self, evaluation: Evaluation) -> str:
        names = ", ".join(f"«{name}»" for name in evaluation.names[:5])
        if evaluation.action is Action.ASK:
            return self._t("shield.ask_unavailable", rules=names or self._t("shield.default_rule"))
        if evaluation.defaulted:
            return self._t("shield.by_default")
        return self._t("shield.by_rule", rules=names)

    def _redacted(
        self, message: Message, evaluation: Evaluation, part: str, context: Context
    ) -> Decision:
        payload = _copy(message.payload)
        if part == "params":
            params = payload.setdefault("params", {})
            if context.phase is Phase.CALL and context.method in TOOL_METHODS:
                params["arguments"] = redact(params.get("arguments"), evaluation.rules, self._home)
            else:
                payload["params"] = redact(params, evaluation.rules, self._home)
        elif "result" in payload:
            payload["result"] = redact(payload["result"], evaluation.rules, self._home)
        else:
            payload["error"] = redact(payload.get("error"), evaluation.rules, self._home)
        self._report(
            self._t(
                "shield.redacted",
                server=self._server,
                method=context.method,
                tool=context.tool or "-",
                rules=", ".join(evaluation.names),
            )
        )
        return Decision(Verdict.FORWARD, Message(message.kind, payload, message.id, message.method))

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
