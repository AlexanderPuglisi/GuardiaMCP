from __future__ import annotations

from dataclasses import dataclass

from guardia.model import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: Severity

    @property
    def category(self) -> str:
        return self.id.split("-", 1)[0]


_C, _H, _M, _L, _I = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

RULES: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule("G01-001", _H),
        Rule("G01-002", _H),
        Rule("G01-003", _H),
        Rule("G01-004", _C),
        Rule("G01-005", _H),
        Rule("G01-006", _M),
        Rule("G02-001", _H),
        Rule("G02-002", _H),
        Rule("G02-003", _H),
        Rule("G02-004", _M),
        Rule("G03-001", _H),
        Rule("G03-002", _I),
        Rule("G03-003", _M),
        Rule("G03-004", _L),
        Rule("G03-005", _H),
        Rule("G03-006", _I),
        Rule("G04-001", _H),
        Rule("G04-002", _M),
        Rule("G04-003", _L),
        Rule("G04-004", _M),
        Rule("G04-005", _H),
        Rule("G05-001", _H),
        Rule("G05-002", _C),
        Rule("G05-003", _H),
        Rule("G05-004", _C),
        Rule("G05-005", _H),
        Rule("G05-006", _M),
        Rule("G05-007", _H),
        Rule("G05-008", _I),
        Rule("G05-009", _C),
        Rule("G05-010", _L),
        Rule("G05-011", _L),
        Rule("G06-001", _H),
        Rule("G06-002", _H),
        Rule("G06-003", _H),
        Rule("G06-004", _H),
        Rule("G06-005", _H),
        Rule("G06-006", _L),
        Rule("G06-007", _H),
        Rule("G06-008", _H),
        Rule("G07-001", _H),
        Rule("G07-002", _H),
        Rule("G07-003", _M),
        Rule("G07-004", _C),
        Rule("G07-005", _H),
        Rule("G07-006", _M),
        Rule("G08-001", _H),
        Rule("G08-002", _M),
        Rule("G08-003", _H),
        Rule("G08-004", _H),
        Rule("G08-005", _M),
        Rule("G08-006", _M),
        Rule("G09-001", _H),
        Rule("G09-002", _H),
        Rule("G09-003", _M),
        Rule("G09-004", _L),
        Rule("G09-005", _L),
        Rule("G09-006", _H),
        Rule("G09-007", _M),
        Rule("G09-008", _M),
        Rule("G09-009", _L),
        Rule("G09-010", _H),
        Rule("G09-011", _H),
        Rule("G09-012", _L),
        Rule("G10-001", _M),
        Rule("G10-002", _M),
        Rule("G10-003", _M),
        Rule("G10-004", _M),
        Rule("G10-005", _M),
        Rule("G10-006", _M),
        Rule("G10-007", _M),
        Rule("G10-008", _M),
        Rule("G10-009", _L),
        Rule("G10-010", _H),
        Rule("G10-011", _L),
        Rule("G11-001", _M),
        Rule("G12-001", _L),
        Rule("G12-002", _L),
        Rule("G12-003", _I),
        Rule("G12-004", _M),
        Rule("G12-005", _H),
        Rule("G12-006", _L),
        Rule("G12-007", _L),
        Rule("G13-001", _H),
        Rule("G13-002", _M),
        Rule("G14-001", _I),
        Rule("G14-002", _M),
        Rule("G14-003", _H),
    )
}
