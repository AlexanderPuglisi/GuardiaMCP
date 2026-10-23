from __future__ import annotations

import difflib
import enum
import re
import tomllib
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from guardia.model import sha256_hex
from guardia.shield.patterns import name_glob, path_glob

SCHEMA_VERSION = 1
MAX_RULES = 500
MAX_PATTERNS = 200
MAX_PATTERN_LENGTH = 500
MAX_NAME_LENGTH = 120
MAX_RATE = 100_000
MAX_RATE_SECONDS = 86_400
MAX_SIZE = 1024 * 1024 * 1024
TOML_LINE = re.compile(r"line (\d+)")


class Action(enum.StrEnum):
    ALLOW = "allow"
    LOG = "log"
    REDACT = "redact"
    ASK = "ask"
    BLOCK = "block"

    @property
    def strength(self) -> int:
        return list(Action).index(self)


class Phase(enum.StrEnum):
    CALL = "call"
    RESULT = "result"
    LIST = "list"
    SERVER_REQUEST = "server_request"


ACTION_NAMES = {
    "consenti": Action.ALLOW,
    "registra": Action.LOG,
    "oscura": Action.REDACT,
    "chiedi": Action.ASK,
    "blocca": Action.BLOCK,
    **{action.value: action for action in Action},
}
PHASE_NAMES = {
    "chiamata": Phase.CALL,
    "risultato": Phase.RESULT,
    "elenco": Phase.LIST,
    "richiesta_server": Phase.SERVER_REQUEST,
    **{phase.value: phase for phase in Phase},
}
DEFAULT_ACTIONS = frozenset({Action.ALLOW, Action.LOG, Action.ASK, Action.BLOCK})
ARGUMENT_PHASES = frozenset({Phase.CALL})

TOP_KEYS = {
    "version": ("versione", "version"),
    "default": ("predefinito", "default"),
    "rules": ("regola", "rule"),
    "protections": ("protezioni", "protections"),
}
RULE_KEYS = {
    "name": ("nome", "name"),
    "action": ("azione", "action"),
    "enabled": ("attiva", "enabled"),
    "note": ("nota", "note"),
    "server": ("server",),
    "tool": ("strumento", "tool"),
    "method": ("metodo", "method"),
    "phase": ("fase", "phase"),
    "argument": ("argomento", "argument"),
    "content": ("contenuto", "content"),
    "rate": ("frequenza", "rate"),
}
ARGUMENT_KEYS = {
    "field": ("campo", "field"),
    "path": ("percorso", "path"),
    "host": ("host",),
    "host_not_in": ("host_non_in", "host_not_in"),
    "contains": ("contiene", "contains"),
    "regex": ("regex",),
}
CONTENT_KEYS = {
    "secrets": ("segreti", "secrets"),
    "contains": ("contiene", "contains"),
    "regex": ("regex",),
    "max_size": ("dimensione_max", "max_size"),
}
RATE_KEYS = {"max": ("massimo", "max"), "seconds": ("secondi", "seconds")}
PROTECTION_KEYS = {
    "approved_tools": ("strumenti_approvati", "approved_tools"),
    "analysis": ("analisi", "analysis"),
    "results": ("risultati", "results"),
    "outgoing_secrets": ("segreti_in_uscita", "outgoing_secrets"),
    "result_secrets": ("segreti_nei_risultati", "result_secrets"),
    "credential_requests": ("richieste_credenziali", "credential_requests"),
}


class Level(enum.StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True, slots=True)
class Issue:
    level: Level
    code: str
    line: int | None = None
    rule: str = ""
    params: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArgumentCondition:
    fields: tuple[re.Pattern[str], ...] = ()
    paths: tuple[re.Pattern[str], ...] = ()
    hosts: tuple[re.Pattern[str], ...] = ()
    hosts_not_in: tuple[re.Pattern[str], ...] = ()
    contains: tuple[str, ...] = ()
    regex: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True, slots=True)
class ContentCondition:
    secrets: bool = False
    contains: tuple[str, ...] = ()
    regex: tuple[re.Pattern[str], ...] = ()
    max_size: int | None = None


@dataclass(frozen=True, slots=True)
class RateLimit:
    maximum: int
    seconds: float


@dataclass(frozen=True, slots=True)
class Rule:
    index: int
    name: str
    action: Action
    line: int | None = None
    servers: tuple[re.Pattern[str], ...] = ()
    tools: tuple[re.Pattern[str], ...] = ()
    methods: tuple[re.Pattern[str], ...] = ()
    phases: frozenset[Phase] = frozenset()
    argument: ArgumentCondition | None = None
    content: ContentCondition | None = None
    rate: RateLimit | None = None


class Sensitivity(enum.StrEnum):
    OFF = "off"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class ResultMode(enum.StrEnum):
    OFF = "off"
    WARN = "warn"
    BLOCK = "block"


SENSITIVITY_NAMES = {
    "spento": Sensitivity.OFF,
    "critico": Sensitivity.CRITICAL,
    "alto": Sensitivity.HIGH,
    "medio": Sensitivity.MEDIUM,
    **{item.value: item for item in Sensitivity},
}
RESULT_MODE_NAMES = {
    "spento": ResultMode.OFF,
    "avvisa": ResultMode.WARN,
    "blocca": ResultMode.BLOCK,
    **{item.value: item for item in ResultMode},
}
OFF_NAMES = frozenset({"spento", "off"})
SECRET_ACTIONS = frozenset({Action.ASK, Action.BLOCK, Action.LOG})
RESULT_SECRET_ACTIONS = frozenset({Action.REDACT})


@dataclass(frozen=True, slots=True)
class Protections:
    approved_tools: bool = True
    analysis: Sensitivity = Sensitivity.HIGH
    results: ResultMode = ResultMode.WARN
    outgoing_secrets: Action | None = Action.ASK
    result_secrets: Action | None = Action.REDACT
    credential_requests: Action | None = Action.BLOCK


@dataclass(frozen=True, slots=True)
class RuleSet:
    default: Action = Action.ALLOW
    rules: tuple[Rule, ...] = ()
    sha256: str = ""
    protections: Protections = field(default_factory=Protections)


@dataclass(slots=True)
class ParseResult:
    ruleset: RuleSet | None
    issues: list[Issue]

    @property
    def errors(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.level is Level.ERROR]


def _bounded_number(value: object, high: int, *, integer: bool) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if integer and not isinstance(value, int):
        return None
    if not 1 <= value <= high:
        return None
    return float(value)


class _Lines:
    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        header = re.compile(r"^\s*\[\[\s*(regola|rule)\s*\]\]", re.IGNORECASE)
        self.headers = [number for number, line in enumerate(self.lines, 1) if header.match(line)]

    def rule(self, index: int) -> int | None:
        return self.headers[index] if index < len(self.headers) else None

    def key(self, index: int, names: tuple[str, ...]) -> int | None:
        start = self.rule(index)
        if start is None:
            return None
        end = self.headers[index + 1] if index + 1 < len(self.headers) else len(self.lines) + 1
        pattern = re.compile(r"^\s*(?:" + "|".join(map(re.escape, names)) + r")\s*[=.\]]")
        for number in range(start, end):
            if pattern.match(self.lines[number - 1]):
                return number
        return start

    def top_table(self, names: tuple[str, ...]) -> int | None:
        alternatives = "|".join(map(re.escape, names))
        pattern = re.compile(rf"^\s*(?:\[\s*(?:{alternatives})\s*\]|(?:{alternatives})\s*[.=])")
        for number, line in enumerate(self.lines, 1):
            if pattern.match(line):
                return number
        return None

    def top(self, names: tuple[str, ...]) -> int | None:
        pattern = re.compile(r"^\s*(?:" + "|".join(map(re.escape, names)) + r")\s*=")
        for number, line in enumerate(self.lines, 1):
            if pattern.match(line):
                return number
        return None


class _Checker:
    def __init__(self, text: str, home: str) -> None:
        self.lines = _Lines(text)
        self.home = home
        self.issues: list[Issue] = []

    def issue(
        self, level: Level, code: str, line: int | None, rule: str = "", **params: object
    ) -> None:
        self.issues.append(Issue(level, code, line, rule, {k: str(v) for k, v in params.items()}))

    def table(
        self,
        table: Mapping[str, Any],
        schema: Mapping[str, tuple[str, ...]],
        line: int | None,
        *,
        rule: str,
        context: str,
        locate: Callable[[str], int | None] | None = None,
    ) -> dict[str, Any]:
        aliases = {alias: canonical for canonical, names in schema.items() for alias in names}
        result: dict[str, Any] = {}
        for key, value in table.items():
            canonical = aliases.get(key)
            if canonical is None:
                suggestion = difflib.get_close_matches(key, list(aliases), n=1, cutoff=0.6)
                self.issue(
                    Level.ERROR,
                    "unknown_key_hint" if suggestion else "unknown_key",
                    locate(key) if locate else line,
                    rule,
                    key=key,
                    context=context,
                    hint=suggestion[0] if suggestion else "",
                )
                continue
            if canonical in result:
                self.issue(
                    Level.ERROR, "duplicate_key", locate(key) if locate else line, rule, key=key
                )
                continue
            result[canonical] = value
        return result

    def strings(self, value: Any, key: str, line: int | None, rule: str) -> tuple[str, ...]:
        items = [value] if isinstance(value, str) else value
        if (
            not isinstance(items, list)
            or not items
            or not all(isinstance(i, str) and i for i in items)
        ):
            self.issue(Level.ERROR, "not_strings", line, rule, key=key)
            return ()
        if len(items) > MAX_PATTERNS:
            self.issue(Level.ERROR, "too_many_patterns", line, rule, key=key, limit=MAX_PATTERNS)
            return ()
        for item in items:
            if len(item) > MAX_PATTERN_LENGTH or "\x00" in item:
                self.issue(
                    Level.ERROR, "pattern_too_long", line, rule, key=key, limit=MAX_PATTERN_LENGTH
                )
                return ()
        return tuple(items)

    def globs(
        self, value: Any, key: str, line: int | None, rule: str
    ) -> tuple[re.Pattern[str], ...]:
        return tuple(name_glob(item) for item in self.strings(value, key, line, rule))

    def regexes(
        self, value: Any, key: str, line: int | None, rule: str
    ) -> tuple[re.Pattern[str], ...]:
        compiled: list[re.Pattern[str]] = []
        for item in self.strings(value, key, line, rule):
            try:
                compiled.append(re.compile(item))
            except re.error as exc:
                self.issue(
                    Level.ERROR, "bad_regex", line, rule, key=key, pattern=item, error=exc.msg
                )
        return tuple(compiled)

    def argument(self, value: Any, index: int, rule: str) -> ArgumentCondition | None:
        line = self.lines.key(index, RULE_KEYS["argument"])
        if not isinstance(value, dict) or not value:
            self.issue(Level.ERROR, "not_table", line, rule, key="argomento")
            return None
        data = self.table(value, ARGUMENT_KEYS, line, rule=rule, context="argomento")
        return ArgumentCondition(
            fields=self.globs(data["field"], "campo", line, rule) if "field" in data else (),
            paths=tuple(
                path_glob(item, self.home)
                for item in (
                    self.strings(data["path"], "percorso", line, rule) if "path" in data else ()
                )
            ),
            hosts=self.globs(data["host"], "host", line, rule) if "host" in data else (),
            hosts_not_in=(
                self.globs(data["host_not_in"], "host_non_in", line, rule)
                if "host_not_in" in data
                else ()
            ),
            contains=(
                tuple(
                    item.lower() for item in self.strings(data["contains"], "contiene", line, rule)
                )
                if "contains" in data
                else ()
            ),
            regex=self.regexes(data["regex"], "regex", line, rule) if "regex" in data else (),
        )

    def content(self, value: Any, index: int, rule: str) -> ContentCondition | None:
        line = self.lines.key(index, RULE_KEYS["content"])
        if not isinstance(value, dict) or not value:
            self.issue(Level.ERROR, "not_table", line, rule, key="contenuto")
            return None
        data = self.table(value, CONTENT_KEYS, line, rule=rule, context="contenuto")
        secrets = data.get("secrets", False)
        if not isinstance(secrets, bool):
            self.issue(Level.ERROR, "not_bool", line, rule, key="segreti")
            secrets = False
        max_size = data.get("max_size")
        if max_size is not None and (
            isinstance(max_size, bool)
            or not isinstance(max_size, int)
            or not 1 <= max_size <= MAX_SIZE
        ):
            self.issue(
                Level.ERROR, "bad_number", line, rule, key="dimensione_max", low=1, high=MAX_SIZE
            )
            max_size = None
        return ContentCondition(
            secrets=secrets,
            contains=(
                tuple(
                    item.lower() for item in self.strings(data["contains"], "contiene", line, rule)
                )
                if "contains" in data
                else ()
            ),
            regex=self.regexes(data["regex"], "regex", line, rule) if "regex" in data else (),
            max_size=max_size,
        )

    def rate(self, value: Any, index: int, rule: str) -> RateLimit | None:
        line = self.lines.key(index, RULE_KEYS["rate"])
        if not isinstance(value, dict):
            self.issue(Level.ERROR, "not_table", line, rule, key="frequenza")
            return None
        data = self.table(value, RATE_KEYS, line, rule=rule, context="frequenza")
        maximum = _bounded_number(data.get("max"), MAX_RATE, integer=True)
        seconds = _bounded_number(data.get("seconds"), MAX_RATE_SECONDS, integer=False)
        if maximum is None:
            self.issue(Level.ERROR, "bad_number", line, rule, key="massimo", low=1, high=MAX_RATE)
        if seconds is None:
            self.issue(
                Level.ERROR, "bad_number", line, rule, key="secondi", low=1, high=MAX_RATE_SECONDS
            )
        if maximum is None or seconds is None:
            return None
        return RateLimit(int(maximum), seconds)

    def name(self, data: Mapping[str, Any], index: int) -> str:
        line = self.lines.key(index, RULE_KEYS["name"])
        value = data.get("name")
        if not isinstance(value, str) or not value.strip():
            self.issue(Level.ERROR, "missing_name", self.lines.rule(index), number=index + 1)
            return f"#{index + 1}"
        if len(value) > MAX_NAME_LENGTH:
            self.issue(Level.ERROR, "name_too_long", line, value[:40], limit=MAX_NAME_LENGTH)
        return value.strip()[:MAX_NAME_LENGTH]

    def action(self, value: Any, line: int | None, rule: str, key: str) -> Action | None:
        if not isinstance(value, str) or value.lower() not in ACTION_NAMES:
            self.issue(Level.ERROR, "bad_action", line, rule, key=key, value=value)
            return None
        return ACTION_NAMES[value.lower()]

    def phases(self, value: Any, line: int | None, rule: str) -> frozenset[Phase]:
        found: set[Phase] = set()
        for item in self.strings(value, "fase", line, rule):
            phase = PHASE_NAMES.get(item.lower())
            if phase is None:
                self.issue(Level.ERROR, "bad_phase", line, rule, value=item)
            else:
                found.add(phase)
        return frozenset(found)

    def rule(self, value: Any, index: int) -> Rule | None:
        start = self.lines.rule(index)
        if not isinstance(value, dict):
            self.issue(Level.ERROR, "not_table", start, key="regola")
            return None
        raw_name = value.get("nome", value.get("name"))
        label = (
            raw_name.strip()[:MAX_NAME_LENGTH]
            if isinstance(raw_name, str) and raw_name.strip()
            else f"#{index + 1}"
        )

        def locate(key: str) -> int | None:
            return self.lines.key(index, (key,))

        data = self.table(value, RULE_KEYS, start, rule=label, context="regola", locate=locate)
        name = self.name(data, index)
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            self.issue(
                Level.ERROR,
                "not_bool",
                self.lines.key(index, RULE_KEYS["enabled"]),
                name,
                key="attiva",
            )
        if "note" in data and not isinstance(data["note"], str):
            self.issue(
                Level.ERROR,
                "not_strings",
                self.lines.key(index, RULE_KEYS["note"]),
                name,
                key="nota",
            )
        if "action" not in data:
            self.issue(Level.ERROR, "missing_action", start, name)
            return None
        action = self.action(
            data["action"], self.lines.key(index, RULE_KEYS["action"]), name, "azione"
        )

        def line_of(key: str) -> int | None:
            return self.lines.key(index, RULE_KEYS[key])

        rule = Rule(
            index=index,
            name=name,
            action=action or Action.BLOCK,
            line=start,
            servers=self.globs(data["server"], "server", line_of("server"), name)
            if "server" in data
            else (),
            tools=self.globs(data["tool"], "strumento", line_of("tool"), name)
            if "tool" in data
            else (),
            methods=self.globs(data["method"], "metodo", line_of("method"), name)
            if "method" in data
            else (),
            phases=self.phases(data["phase"], line_of("phase"), name)
            if "phase" in data
            else frozenset(),
            argument=self.argument(data["argument"], index, name) if "argument" in data else None,
            content=self.content(data["content"], index, name) if "content" in data else None,
            rate=self.rate(data["rate"], index, name) if "rate" in data else None,
        )
        self.warnings(rule)
        return rule if action is not None and enabled is True else None

    def choice(self, value: Any, names: Mapping[str, Any], key: str, line: int | None) -> Any:
        if not isinstance(value, str) or value.lower() not in names:
            options = ", ".join(sorted(names))
            self.issue(Level.ERROR, "bad_choice", line, key=key, value=value, options=options)
            return None
        return names[value.lower()]

    def secret_action(
        self, value: Any, allowed: frozenset[Action], key: str, line: int | None
    ) -> tuple[bool, Action | None]:
        names: dict[str, Action | None] = {
            name: action for name, action in ACTION_NAMES.items() if action in allowed
        }
        names.update(dict.fromkeys(OFF_NAMES, None))
        if not isinstance(value, str) or value.lower() not in names:
            options = ", ".join(sorted(names))
            self.issue(Level.ERROR, "bad_choice", line, key=key, value=value, options=options)
            return False, None
        return True, names[value.lower()]

    def protections(self, value: Any) -> Protections:
        line = self.lines.top_table(TOP_KEYS["protections"])
        if not isinstance(value, dict):
            self.issue(Level.ERROR, "not_table", line, key="protezioni")
            return Protections()
        data = self.table(value, PROTECTION_KEYS, line, rule="", context="protezioni")
        result = Protections()
        if "approved_tools" in data:
            if isinstance(data["approved_tools"], bool):
                result = replace(result, approved_tools=data["approved_tools"])
            else:
                self.issue(Level.ERROR, "not_bool", line, key="strumenti_approvati")
        if "analysis" in data:
            chosen = self.choice(data["analysis"], SENSITIVITY_NAMES, "analisi", line)
            result = replace(result, analysis=chosen or result.analysis)
        if "results" in data:
            chosen = self.choice(data["results"], RESULT_MODE_NAMES, "risultati", line)
            result = replace(result, results=chosen or result.results)
        if "outgoing_secrets" in data:
            valid, action = self.secret_action(
                data["outgoing_secrets"], SECRET_ACTIONS, "segreti_in_uscita", line
            )
            result = replace(result, outgoing_secrets=action) if valid else result
        if "result_secrets" in data:
            valid, action = self.secret_action(
                data["result_secrets"], RESULT_SECRET_ACTIONS, "segreti_nei_risultati", line
            )
            result = replace(result, result_secrets=action) if valid else result
        if "credential_requests" in data:
            valid, action = self.secret_action(
                data["credential_requests"], SECRET_ACTIONS, "richieste_credenziali", line
            )
            result = replace(result, credential_requests=action) if valid else result
        self.relaxed(result, line)
        return result

    def relaxed(self, protections: Protections, line: int | None) -> None:
        checks = (
            ("strumenti_approvati", protections.approved_tools is False),
            ("analisi", protections.analysis in (Sensitivity.OFF, Sensitivity.CRITICAL)),
            ("risultati", protections.results is ResultMode.OFF),
            ("segreti_in_uscita", protections.outgoing_secrets in (None, Action.LOG)),
            ("segreti_nei_risultati", protections.result_secrets is None),
            ("richieste_credenziali", protections.credential_requests in (None, Action.LOG)),
        )
        for key, weaker in checks:
            if weaker:
                self.issue(Level.WARNING, "protection_relaxed", line, key=key)

    def warnings(self, rule: Rule) -> None:
        if rule.argument is not None and rule.phases and not rule.phases & ARGUMENT_PHASES:
            self.issue(Level.WARNING, "argument_never_matches", rule.line, rule.name)
        if rule.action is Action.REDACT and rule.phases == frozenset({Phase.LIST}):
            self.issue(Level.ERROR, "redact_on_list", rule.line, rule.name)
        has_condition = any(
            (
                rule.servers,
                rule.tools,
                rule.methods,
                rule.phases,
                rule.argument,
                rule.content,
                rule.rate,
            )
        )
        if not has_condition:
            self.issue(Level.WARNING, "matches_everything", rule.line, rule.name)
        if rule.action is Action.REDACT and rule.argument is None and rule.content is None:
            self.issue(Level.WARNING, "redacts_everything", rule.line, rule.name)


def _toml_line(error: tomllib.TOMLDecodeError) -> int | None:
    match = TOML_LINE.search(str(error))
    return int(match.group(1)) if match else None


def _top(
    checker: _Checker, document: dict[str, Any]
) -> tuple[Action, list[Any], Protections] | None:
    if all(name in document for name in TOP_KEYS["rules"]):
        checker.issue(Level.ERROR, "mixed_rule_tables", checker.lines.rule(0))
        return None
    data = checker.table(document, TOP_KEYS, None, rule="", context="file")
    version = data.get("version")
    if version != SCHEMA_VERSION or isinstance(version, bool):
        checker.issue(
            Level.ERROR,
            "bad_version",
            checker.lines.top(TOP_KEYS["version"]),
            value=version,
            expected=SCHEMA_VERSION,
        )
        return None
    default = Action.ALLOW
    if "default" in data:
        line = checker.lines.top(TOP_KEYS["default"])
        parsed = checker.action(data["default"], line, "", "predefinito")
        if parsed is not None and parsed not in DEFAULT_ACTIONS:
            checker.issue(Level.ERROR, "bad_default", line, value=data["default"])
        elif parsed is not None:
            default = parsed
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        checker.issue(Level.ERROR, "not_table", None, key="regola")
        return None
    if len(rules) > MAX_RULES:
        checker.issue(Level.ERROR, "too_many_rules", None, limit=MAX_RULES)
        return None
    protections = (
        checker.protections(data["protections"]) if "protections" in data else Protections()
    )
    return default, rules, protections


def parse_rules(text: str, home: str) -> ParseResult:
    checker = _Checker(text, home)
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        checker.issue(Level.ERROR, "toml", _toml_line(exc), error=str(exc))
        return ParseResult(None, checker.issues)
    top = _top(checker, document)
    if top is None:
        return ParseResult(None, checker.issues)
    default, raw_rules, protections = top
    rules = [rule for index, item in enumerate(raw_rules) if (rule := checker.rule(item, index))]
    names = [rule.name for rule in rules]
    for name in sorted({name for name in names if names.count(name) > 1}):
        checker.issue(Level.WARNING, "duplicate_name", None, name)
    if any(issue.level is Level.ERROR for issue in checker.issues):
        return ParseResult(None, checker.issues)
    ruleset = RuleSet(default, tuple(rules), sha256_hex(text.encode("utf-8")), protections)
    return ParseResult(ruleset, checker.issues)


def all_keys() -> Iterator[str]:
    for schema in (TOP_KEYS, RULE_KEYS, ARGUMENT_KEYS, CONTENT_KEYS, RATE_KEYS, PROTECTION_KEYS):
        for names in schema.values():
            yield from names
