from __future__ import annotations

import re
from collections.abc import Iterator

from guardia.i18n import Translator
from guardia.model import Severity
from guardia.render.terminal import severity_label
from guardia.scanner import RULES
from guardia.scanner.rules import Rule

PLACEHOLDER = re.compile(r"\{\{?(\w+)\}?\}")
MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")
GUIDE_SECTIONS = ("read", "code", "what", "false", "shield")
TERMS = (
    "tool_poisoning",
    "prompt_injection",
    "rug_pull",
    "shadowing",
    "typosquatting",
    "secret",
    "baseline",
    "skill",
)


def generic(text: str) -> str:
    return PLACEHOLDER.sub("…", text)


def _escape(text: str) -> str:
    return MARKDOWN_SPECIAL.sub(r"\\\1", text)


def rule_text(rule: Rule, part: str, t: Translator) -> str:
    return generic(t(f"rules.{rule.id}.{part}"))


def categories() -> dict[str, list[Rule]]:
    grouped: dict[str, list[Rule]] = {}
    for rule_id in sorted(RULES):
        rule = RULES[rule_id]
        grouped.setdefault(rule.category, []).append(rule)
    return grouped


def _guide_intro(t: Translator) -> Iterator[str]:
    yield f"# {t('guide.title')}"
    yield ""
    yield t("guide.intro", count=len(RULES))
    yield ""
    yield f"## {t('guide.levels_title')}"
    yield ""
    yield f"| {t('guide.level')} | {t('guide.meaning')} |"
    yield "|---|---|"
    for severity in sorted(Severity, reverse=True):
        yield f"| **{severity_label(severity, t)}** | {t(f'guide.level_{severity.label}')} |"
    for section in GUIDE_SECTIONS:
        yield ""
        yield f"## {t(f'guide.{section}_title')}"
        yield ""
        yield t(f"guide.{section}_text").strip()
    yield ""
    yield f"## {t('guide.terms_title')}"
    yield ""
    for term in TERMS:
        yield f"- **{t(f'guide.term_{term}')}** — {t(f'guide.term_{term}_text')}"


def _count(count: int, t: Translator) -> str:
    return t("guide.family_count_one") if count == 1 else t("guide.family_count", count=count)


def render_rules_markdown(t: Translator) -> str:
    lines = list(_guide_intro(t))
    grouped = categories()
    lines += ["", f"## {t('guide.families_title')}", ""]
    lines += [
        f"- **{code}** — {t(f'category.{code}')}: {_count(len(rules), t)}"
        for code, rules in grouped.items()
    ]
    for code, rules in grouped.items():
        lines += ["", f"## {code} — {t(f'category.{code}')}"]
        for rule in rules:
            label = severity_label(rule.severity, t)
            lines += [
                "",
                f"### {rule.id} · {label} — {_escape(rule_text(rule, 'title', t))}",
                "",
                f"**{t('scan.why')}.** {_escape(rule_text(rule, 'why', t))}",
                "",
                f"**{t('scan.fix')}.** {_escape(rule_text(rule, 'fix', t))}",
            ]
    lines += ["", "---", "", t("guide.footer")]
    return "\n".join(lines) + "\n"


def render_rules_list(t: Translator) -> str:
    lines = [t("guide.title"), ""]
    for code, rules in categories().items():
        lines.append(f"{code} — {t(f'category.{code}')}")
        for rule in rules:
            label = severity_label(rule.severity, t)
            lines.append(f"  {rule.id}  {label:<8} {rule_text(rule, 'title', t)}")
        lines.append("")
    lines.append(t("guide.list_hint"))
    return "\n".join(lines) + "\n"


def render_rule_detail(rule_id: str, t: Translator) -> str:
    rule = RULES[rule_id]
    return (
        "\n".join(
            [
                f"{rule.id} · {severity_label(rule.severity, t)} — {rule_text(rule, 'title', t)}",
                t("guide.family_line", code=rule.category, name=t(f"category.{rule.category}")),
                "",
                f"{t('scan.why')}: {rule_text(rule, 'why', t)}",
                "",
                f"{t('scan.fix')}: {rule_text(rule, 'fix', t)}",
            ]
        )
        + "\n"
    )
