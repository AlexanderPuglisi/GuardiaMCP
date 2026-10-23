from __future__ import annotations

import re
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from guardia.redact import REDACTED, SECRET_VALUE
from guardia.shield.patterns import Leaf, hosts_in, leaves, normalize_path
from guardia.shield.rules import (
    Action,
    ArgumentCondition,
    ContentCondition,
    Phase,
    Rule,
    RuleSet,
)

MAX_TRACKED_WINDOWS = 10_000


@dataclass(frozen=True, slots=True)
class Context:
    phase: Phase
    server: str
    method: str = ""
    tool: str = ""
    arguments: Any = None
    content: Any = None
    size: int = 0


@dataclass(frozen=True, slots=True)
class Evaluation:
    action: Action
    rules: tuple[Rule, ...] = ()
    defaulted: bool = False

    @property
    def names(self) -> list[str]:
        return [rule.name for rule in self.rules]


def _any_name(patterns: Iterable[re.Pattern[str]], value: str) -> bool:
    return any(pattern.fullmatch(value) for pattern in patterns)


def _selected(condition: ArgumentCondition, found: list[Leaf]) -> list[Leaf]:
    if not condition.fields:
        return found
    return [leaf for leaf in found if any(_any_name(condition.fields, key) for key in leaf.keys)]


def _text_hits(
    contains: tuple[str, ...], regex: tuple[re.Pattern[str], ...], found: list[Leaf]
) -> bool:
    if contains and not any(word in leaf.text.lower() for leaf in found for word in contains):
        return False
    return not regex or any(pattern.search(leaf.text) for leaf in found for pattern in regex)


def _path_hit(condition: ArgumentCondition, text: str, home: str) -> bool:
    normalized = normalize_path(text, home)
    return normalized is not None and any(
        pattern.fullmatch(normalized) for pattern in condition.paths
    )


def _foreign_host(condition: ArgumentCondition, host: str) -> bool:
    return not _any_name(condition.hosts_not_in, host)


def argument_matches(condition: ArgumentCondition, value: Any, home: str) -> bool:
    found = _selected(condition, leaves(value))
    if not found:
        return False
    if condition.paths and not any(_path_hit(condition, leaf.text, home) for leaf in found):
        return False
    if condition.hosts and not any(
        _any_name(condition.hosts, host) for leaf in found for host in hosts_in(leaf.text)
    ):
        return False
    if condition.hosts_not_in and not any(
        _foreign_host(condition, host) for leaf in found for host in hosts_in(leaf.text)
    ):
        return False
    return _text_hits(condition.contains, condition.regex, found)


def content_matches(condition: ContentCondition, value: Any, size: int) -> bool:
    if condition.max_size is not None and size <= condition.max_size:
        return False
    found = leaves(value)
    if condition.secrets and not any(SECRET_VALUE.search(leaf.text) for leaf in found):
        return False
    return _text_hits(condition.contains, condition.regex, found)


def conditions_match(rule: Rule, context: Context, home: str) -> bool:
    if rule.phases and context.phase not in rule.phases:
        return False
    if rule.servers and not _any_name(rule.servers, context.server):
        return False
    if rule.tools and not (context.tool and _any_name(rule.tools, context.tool)):
        return False
    if rule.methods and not _any_name(rule.methods, context.method):
        return False
    if rule.argument is not None and (
        context.phase is not Phase.CALL
        or not argument_matches(rule.argument, context.arguments, home)
    ):
        return False
    return rule.content is None or content_matches(rule.content, context.content, context.size)


@dataclass
class Engine:
    ruleset: RuleSet
    home: str
    clock: Callable[[], float] = time.monotonic
    _windows: dict[tuple[int, str], deque[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _over_rate(self, rule: Rule, server: str, record: bool) -> bool:
        if rule.rate is None:
            return True
        now = self.clock()
        with self._lock:
            window = self._windows.get((rule.index, server))
            if window is None:
                if len(self._windows) >= MAX_TRACKED_WINDOWS:
                    self._windows.clear()
                window = self._windows.setdefault((rule.index, server), deque())
            while window and now - window[0] > rule.rate.seconds:
                window.popleft()
            if record:
                window.append(now)
                return len(window) > rule.rate.maximum
            return len(window) + 1 > rule.rate.maximum

    def evaluate(self, context: Context, *, record: bool = True) -> Evaluation:
        matched = [
            rule
            for rule in self.ruleset.rules
            if conditions_match(rule, context, self.home)
            and self._over_rate(rule, context.server, record)
        ]
        if not matched:
            default = Action.ALLOW if context.phase is Phase.RESULT else self.ruleset.default
            return Evaluation(default, (), defaulted=True)
        strongest = max(matched, key=lambda rule: rule.action.strength).action
        return Evaluation(strongest, tuple(matched))


def _redact_text(rule: Rule, keys: tuple[str, ...], text: str, home: str) -> str:
    if rule.argument is None and rule.content is None:
        return REDACTED
    condition = rule.argument
    if condition is not None and (
        not condition.fields or any(_any_name(condition.fields, key) for key in keys)
    ):
        if condition.paths and _path_hit(condition, text, home):
            return REDACTED
        for host in set(hosts_in(text)):
            if _any_name(condition.hosts, host) or (
                condition.hosts_not_in and _foreign_host(condition, host)
            ):
                text = re.sub(
                    r"[a-z][a-z0-9+.-]*://[^\s\"'<>`]*" + re.escape(host) + r"[^\s\"'<>`]*",
                    REDACTED,
                    text,
                    flags=re.IGNORECASE,
                )
        text = _redact_words(text, condition.contains, condition.regex)
    content = rule.content
    if content is not None:
        if content.secrets:
            text = SECRET_VALUE.sub(REDACTED, text)
        text = _redact_words(text, content.contains, content.regex)
    return text


def _redact_words(text: str, contains: tuple[str, ...], regex: tuple[re.Pattern[str], ...]) -> str:
    for word in contains:
        text = re.sub(re.escape(word), REDACTED, text, flags=re.IGNORECASE)
    for pattern in regex:
        text = pattern.sub(REDACTED, text)
    return text


def redact(value: Any, rules: Iterable[Rule], home: str, keys: tuple[str, ...] = ()) -> Any:
    active = [rule for rule in rules if rule.action is Action.REDACT]
    if isinstance(value, str):
        for rule in active:
            value = _redact_text(rule, keys, value, home)
        return value
    if isinstance(value, dict):
        return {key: redact(item, active, home, (*keys, str(key))) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, active, home, keys) for item in value]
    return value
