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


ACTION_WORDS = {
    Action.ALLOW: "consenti",
    Action.LOG: "registra",
    Action.REDACT: "oscura",
    Action.ASK: "chiedi",
    Action.BLOCK: "blocca",
}
ACTION_NAMES = {
    **{word: action for action, word in ACTION_WORDS.items()},
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
RATE_PHASES = frozenset({Phase.CALL, Phase.SERVER_REQUEST})

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


SENSITIVITY_WORDS = {
    Sensitivity.OFF: "spento",
    Sensitivity.CRITICAL: "critico",
    Sensitivity.HIGH: "alto",
    Sensitivity.MEDIUM: "medio",
}
SENSITIVITY_NAMES = {
    **{word: item for item, word in SENSITIVITY_WORDS.items()},
    **{item.value: item for item in Sensitivity},
}
RESULT_MODE_WORDS = {
    ResultMode.OFF: "spento",
    ResultMode.WARN: "avvisa",
    ResultMode.BLOCK: "blocca",
}
RESULT_MODE_NAMES = {
    **{word: item for item, word in RESULT_MODE_WORDS.items()},
    **{item.value: item for item in ResultMode},
}
OFF_NAMES = frozenset({"spento", "off"})
OFF_WORDS = ("spento", "off")
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


def _either(names: tuple[str, ...]) -> str:
    return "|".join(map(re.escape, names))


RULE_TABLE = _either(("regola", "rule"))
SUB_TABLE = re.compile(rf"^\s*\[\s*(?:{RULE_TABLE})\s*\.")
TABLE_HEADER = re.compile(r"^\s*\[\[?\s*[\w\-. \"']+\]\]?\s*(?:#.*)?$")


class _Lines:
    def __init__(self, text: str) -> None:
        self.lines = text.splitlines()
        header = re.compile(rf"^\s*\[\[\s*(?:{RULE_TABLE})\s*\]\]", re.IGNORECASE)
        self.headers = [number for number, line in enumerate(self.lines, 1) if header.match(line)]
        self.first_table = next(
            (number for number, line in enumerate(self.lines, 1) if TABLE_HEADER.match(line)),
            len(self.lines) + 1,
        )

    def rule(self, index: int) -> int | None:
        return self.headers[index] if index < len(self.headers) else None

    def span(self, index: int) -> tuple[int, int] | None:
        start = self.rule(index)
        if start is None:
            return None
        for number in range(start + 1, len(self.lines) + 1):
            line = self.lines[number - 1]
            if TABLE_HEADER.match(line) and not SUB_TABLE.match(line):
                return start, number
        return start, len(self.lines) + 1

    def key(self, index: int, names: tuple[str, ...]) -> int | None:
        span = self.span(index)
        if span is None:
            return None
        start, end = span
        alternatives = _either(names)
        pattern = re.compile(
            rf"^\s*(?:(?:{alternatives})\s*[=.]|\[\s*(?:{RULE_TABLE})\s*\.\s*(?:{alternatives})\s*[\].])"
        )
        for number in range(start, end):
            if pattern.match(self.lines[number - 1]):
                return number
        return start

    def sub_key(self, index: int, parent: tuple[str, ...], child: tuple[str, ...]) -> int | None:
        span = self.span(index)
        if span is None:
            return None
        start, end = span
        dotted = re.compile(rf"^\s*(?:{_either(parent)})\s*\.\s*(?:{_either(child)})\s*=")
        header = re.compile(rf"^\s*\[\s*(?:{RULE_TABLE})\s*\.\s*(?:{_either(parent)})\s*\]")
        inside = re.compile(rf"^\s*(?:{_either(child)})\s*=")
        within = False
        for number in range(start, end):
            line = self.lines[number - 1]
            if dotted.match(line):
                return number
            if TABLE_HEADER.match(line):
                within = bool(header.match(line))
            elif within and inside.match(line):
                return number
        return self.key(index, parent)

    def table_key(self, table: tuple[str, ...], names: tuple[str, ...]) -> int | None:
        dotted = re.compile(rf"^\s*(?:{_either(table)})\s*\.\s*(?:{_either(names)})\s*=")
        header = re.compile(rf"^\s*\[\s*(?:{_either(table)})\s*\]")
        inside = re.compile(rf"^\s*(?:{_either(names)})\s*=")
        within = False
        for number, line in enumerate(self.lines, 1):
            if dotted.match(line) and number < self.first_table:
                return number
            if TABLE_HEADER.match(line):
                within = bool(header.match(line))
            elif within and inside.match(line):
                return number
        return self.top_table(table)

    def top_table(self, names: tuple[str, ...]) -> int | None:
        alternatives = _either(names)
        pattern = re.compile(rf"^\s*(?:\[\s*(?:{alternatives})\s*\]|(?:{alternatives})\s*[.=])")
        for number, line in enumerate(self.lines, 1):
            if pattern.match(line):
                return number
        return None

    def top(self, names: tuple[str, ...]) -> int | None:
        pattern = re.compile(rf"^\s*(?:{_either(names)})\s*=")
        for number, line in enumerate(self.lines[: self.first_table - 1], 1):
            if pattern.match(line):
                return number
        return None

    def top_any(self, name: str) -> int | None:
        escaped = re.escape(name)
        plain = re.compile(rf"^\s*{escaped}\s*[.=]")
        table = re.compile(rf"^\s*\[\[?\s*{escaped}\s*[\].]")
        for number, line in enumerate(self.lines, 1):
            if (number < self.first_table and plain.match(line)) or table.match(line):
                return number
        return None


def _english(written: str, names: tuple[str, ...], fallback: bool) -> bool:
    if len(set(names)) == 1:
        return fallback
    return written == names[-1]


class _Table(dict[str, Any]):
    def __init__(self, schema: Mapping[str, tuple[str, ...]], english: bool) -> None:
        super().__init__()
        self.schema = schema
        self.english = english
        self.written: dict[str, str] = {}

    def name(self, canonical: str) -> str:
        if canonical in self.written:
            return self.written[canonical]
        names = self.schema[canonical]
        return names[-1] if self.english else names[0]

    def inner(self, canonical: str) -> bool:
        return _english(self.name(canonical), self.schema[canonical], self.english)


class _Checker:
    def __init__(self, text: str, home: str) -> None:
        self.lines = _Lines(text)
        self.home = home
        self.issues: list[Issue] = []
        self.english = False

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
        english: bool,
        locate: Callable[[str], int | None] | None = None,
    ) -> _Table:
        aliases = {alias: canonical for canonical, names in schema.items() for alias in names}
        result = _Table(schema, english)
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
            result.written[canonical] = key
        return result

    def words(self, values: Mapping[Any, str], english: bool, extra: tuple[str, ...] = ()) -> str:
        names = [item.value if english else word for item, word in values.items()]
        return ", ".join([*names, *extra])

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

    def section(
        self,
        rule_data: _Table,
        canonical: str,
        schema: Mapping[str, tuple[str, ...]],
        index: int,
        rule: str,
    ) -> tuple[_Table | None, Callable[[str], int | None]]:
        parent = RULE_KEYS[canonical]
        key = rule_data.name(canonical)
        line = self.lines.key(index, parent)
        value = rule_data[canonical]

        def at(child: str) -> int | None:
            return self.lines.sub_key(index, parent, schema.get(child, (child,)))

        if not isinstance(value, dict) or (canonical != "rate" and not value):
            self.issue(Level.ERROR, "not_table", line, rule, key=key)
            return None, at
        data = self.table(
            value,
            schema,
            line,
            rule=rule,
            context=key,
            english=rule_data.inner(canonical),
            locate=at,
        )
        return data, at

    def texts(
        self, data: _Table, canonical: str, at: Callable[[str], int | None], rule: str
    ) -> tuple[str, ...]:
        if canonical not in data:
            return ()
        return self.strings(data[canonical], data.name(canonical), at(canonical), rule)

    def argument(self, rule_data: _Table, index: int, rule: str) -> ArgumentCondition | None:
        data, at = self.section(rule_data, "argument", ARGUMENT_KEYS, index, rule)
        if data is None:
            return None

        def names(canonical: str) -> tuple[re.Pattern[str], ...]:
            return tuple(name_glob(item) for item in self.texts(data, canonical, at, rule))

        return ArgumentCondition(
            fields=names("field"),
            paths=tuple(path_glob(item, self.home) for item in self.texts(data, "path", at, rule)),
            hosts=names("host"),
            hosts_not_in=names("host_not_in"),
            contains=tuple(item.lower() for item in self.texts(data, "contains", at, rule)),
            regex=self.patterns(data, at, rule),
        )

    def patterns(
        self, data: _Table, at: Callable[[str], int | None], rule: str
    ) -> tuple[re.Pattern[str], ...]:
        if "regex" not in data:
            return ()
        return self.regexes(data["regex"], data.name("regex"), at("regex"), rule)

    def content(self, rule_data: _Table, index: int, rule: str) -> ContentCondition | None:
        data, at = self.section(rule_data, "content", CONTENT_KEYS, index, rule)
        if data is None:
            return None
        secrets = data.get("secrets", False)
        if not isinstance(secrets, bool):
            self.issue(Level.ERROR, "not_bool", at("secrets"), rule, key=data.name("secrets"))
            secrets = False
        max_size = data.get("max_size")
        if max_size is not None and (
            isinstance(max_size, bool)
            or not isinstance(max_size, int)
            or not 1 <= max_size <= MAX_SIZE
        ):
            self.issue(
                Level.ERROR,
                "bad_number",
                at("max_size"),
                rule,
                key=data.name("max_size"),
                low=1,
                high=MAX_SIZE,
            )
            max_size = None
        return ContentCondition(
            secrets=secrets,
            contains=tuple(item.lower() for item in self.texts(data, "contains", at, rule)),
            regex=self.patterns(data, at, rule),
            max_size=max_size,
        )

    def rate(self, rule_data: _Table, index: int, rule: str) -> RateLimit | None:
        data, at = self.section(rule_data, "rate", RATE_KEYS, index, rule)
        if data is None:
            return None
        maximum = _bounded_number(data.get("max"), MAX_RATE, integer=True)
        seconds = _bounded_number(data.get("seconds"), MAX_RATE_SECONDS, integer=False)
        if maximum is None:
            self.issue(
                Level.ERROR,
                "bad_number",
                at("max"),
                rule,
                key=data.name("max"),
                low=1,
                high=MAX_RATE,
            )
        if seconds is None:
            self.issue(
                Level.ERROR,
                "bad_number",
                at("seconds"),
                rule,
                key=data.name("seconds"),
                low=1,
                high=MAX_RATE_SECONDS,
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

    def phases(self, value: Any, line: int | None, rule: str, key: str) -> frozenset[Phase]:
        found: set[Phase] = set()
        for item in self.strings(value, key, line, rule):
            phase = PHASE_NAMES.get(item.lower())
            if phase is None:
                self.issue(Level.ERROR, "bad_phase", line, rule, value=item)
            else:
                found.add(phase)
        return frozenset(found)

    def rule(self, value: Any, index: int) -> Rule | None:
        start = self.lines.rule(index)
        if not isinstance(value, dict):
            self.issue(Level.ERROR, "not_table", start, key="rule" if self.english else "regola")
            return None
        raw_name = value.get("nome", value.get("name"))
        label = (
            raw_name.strip()[:MAX_NAME_LENGTH]
            if isinstance(raw_name, str) and raw_name.strip()
            else f"#{index + 1}"
        )

        def locate(key: str) -> int | None:
            return self.lines.key(index, (key,))

        data = self.table(
            value,
            RULE_KEYS,
            start,
            rule=label,
            context="rule" if self.english else "regola",
            english=self.english,
            locate=locate,
        )
        name = self.name(data, index)

        def line_of(key: str) -> int | None:
            return self.lines.key(index, RULE_KEYS[key])

        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            self.issue(Level.ERROR, "not_bool", line_of("enabled"), name, key=data.name("enabled"))
        if "note" in data and not isinstance(data["note"], str):
            self.issue(Level.ERROR, "not_strings", line_of("note"), name, key=data.name("note"))
        if "action" not in data:
            self.issue(Level.ERROR, "missing_action", start, name)
            return None
        action = self.action(data["action"], line_of("action"), name, data.name("action"))

        def names(key: str) -> tuple[re.Pattern[str], ...]:
            if key not in data:
                return ()
            return self.globs(data[key], data.name(key), line_of(key), name)

        rule = Rule(
            index=index,
            name=name,
            action=action or Action.BLOCK,
            line=start,
            servers=names("server"),
            tools=names("tool"),
            methods=names("method"),
            phases=self.phases(data["phase"], line_of("phase"), name, data.name("phase"))
            if "phase" in data
            else frozenset(),
            argument=self.argument(data, index, name) if "argument" in data else None,
            content=self.content(data, index, name) if "content" in data else None,
            rate=self.rate(data, index, name) if "rate" in data else None,
        )
        self.warnings(rule)
        return rule if action is not None and enabled is True else None

    def choice(
        self,
        value: Any,
        names: Mapping[str, Any],
        words: Mapping[Any, str],
        data: _Table,
        key: str,
    ) -> Any:
        if not isinstance(value, str) or value.lower() not in names:
            line = self.lines.table_key(TOP_KEYS["protections"], PROTECTION_KEYS[key])
            options = self.words(words, data.inner(key))
            self.issue(
                Level.ERROR, "bad_choice", line, key=data.name(key), value=value, options=options
            )
            return None
        return names[value.lower()]

    def secret_action(
        self, value: Any, allowed: frozenset[Action], data: _Table, key: str
    ) -> tuple[bool, Action | None]:
        names: dict[str, Action | None] = {
            name: action for name, action in ACTION_NAMES.items() if action in allowed
        }
        names.update(dict.fromkeys(OFF_NAMES, None))
        if not isinstance(value, str) or value.lower() not in names:
            english = data.inner(key)
            words = {action: word for action, word in ACTION_WORDS.items() if action in allowed}
            options = self.words(words, english, (OFF_WORDS[1] if english else OFF_WORDS[0],))
            line = self.lines.table_key(TOP_KEYS["protections"], PROTECTION_KEYS[key])
            self.issue(
                Level.ERROR, "bad_choice", line, key=data.name(key), value=value, options=options
            )
            return False, None
        return True, names[value.lower()]

    def protections(self, value: Any, english: bool, key: str) -> Protections:
        line = self.lines.top_table(TOP_KEYS["protections"])
        if not isinstance(value, dict):
            self.issue(Level.ERROR, "not_table", line, key=key)
            return Protections()

        def at(name: str) -> int | None:
            return self.lines.table_key(TOP_KEYS["protections"], (name,))

        data = self.table(
            value, PROTECTION_KEYS, line, rule="", context=key, english=english, locate=at
        )
        result = Protections()
        if "approved_tools" in data:
            if isinstance(data["approved_tools"], bool):
                result = replace(result, approved_tools=data["approved_tools"])
            else:
                where = self.lines.table_key(
                    TOP_KEYS["protections"], PROTECTION_KEYS["approved_tools"]
                )
                self.issue(Level.ERROR, "not_bool", where, key=data.name("approved_tools"))
        if "analysis" in data:
            chosen = self.choice(
                data["analysis"], SENSITIVITY_NAMES, SENSITIVITY_WORDS, data, "analysis"
            )
            result = replace(result, analysis=chosen or result.analysis)
        if "results" in data:
            chosen = self.choice(
                data["results"], RESULT_MODE_NAMES, RESULT_MODE_WORDS, data, "results"
            )
            result = replace(result, results=chosen or result.results)
        if "outgoing_secrets" in data:
            valid, action = self.secret_action(
                data["outgoing_secrets"], SECRET_ACTIONS, data, "outgoing_secrets"
            )
            result = replace(result, outgoing_secrets=action) if valid else result
        if "result_secrets" in data:
            valid, action = self.secret_action(
                data["result_secrets"], RESULT_SECRET_ACTIONS, data, "result_secrets"
            )
            result = replace(result, result_secrets=action) if valid else result
        if "credential_requests" in data:
            valid, action = self.secret_action(
                data["credential_requests"], SECRET_ACTIONS, data, "credential_requests"
            )
            result = replace(result, credential_requests=action) if valid else result
        self.relaxed(result, data)
        return result

    def relaxed(self, protections: Protections, data: _Table) -> None:
        checks = (
            ("approved_tools", protections.approved_tools is False),
            ("analysis", protections.analysis in (Sensitivity.OFF, Sensitivity.CRITICAL)),
            ("results", protections.results is ResultMode.OFF),
            ("outgoing_secrets", protections.outgoing_secrets in (None, Action.LOG)),
            ("result_secrets", protections.result_secrets is None),
            ("credential_requests", protections.credential_requests in (None, Action.LOG)),
        )
        for key, weaker in checks:
            if weaker:
                line = self.lines.table_key(TOP_KEYS["protections"], PROTECTION_KEYS[key])
                self.issue(Level.WARNING, "protection_relaxed", line, key=data.name(key))

    def warnings(self, rule: Rule) -> None:
        if rule.argument is not None and rule.phases and not rule.phases & ARGUMENT_PHASES:
            self.issue(Level.WARNING, "argument_never_matches", rule.line, rule.name)
        if rule.rate is not None and rule.phases and not rule.phases & RATE_PHASES:
            self.issue(Level.WARNING, "rate_never_matches", rule.line, rule.name)
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


def _file_english(document: Mapping[str, Any]) -> bool:
    english = sum(names[-1] in document for names in TOP_KEYS.values())
    italian = sum(names[0] in document for names in TOP_KEYS.values())
    return english > italian


def _top(
    checker: _Checker, document: dict[str, Any]
) -> tuple[Action, list[Any], Protections] | None:
    checker.english = _file_english(document)
    if all(name in document for name in TOP_KEYS["rules"]):
        checker.issue(Level.ERROR, "mixed_rule_tables", checker.lines.rule(0))
        return None
    data = checker.table(
        document,
        TOP_KEYS,
        None,
        rule="",
        context="file",
        english=checker.english,
        locate=checker.lines.top_any,
    )
    if "rules" in data:
        checker.english = data.inner("rules")
    if "version" not in data:
        checker.issue(
            Level.ERROR, "missing_version", 1, key=data.name("version"), expected=SCHEMA_VERSION
        )
        return None
    version = data["version"]
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
        parsed = checker.action(data["default"], line, "", data.name("default"))
        if parsed is not None and parsed not in DEFAULT_ACTIONS:
            checker.issue(Level.ERROR, "bad_default", line, value=data["default"])
        elif parsed is not None:
            default = parsed
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        line = checker.lines.top_any(data.name("rules"))
        checker.issue(Level.ERROR, "not_table", line, key=data.name("rules"))
        return None
    if len(rules) > MAX_RULES:
        checker.issue(Level.ERROR, "too_many_rules", checker.lines.rule(MAX_RULES), limit=MAX_RULES)
        return None
    protections = (
        checker.protections(
            data["protections"], data.inner("protections"), data.name("protections")
        )
        if "protections" in data
        else Protections()
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
