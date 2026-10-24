from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from guardia.cli import main
from guardia.i18n import Translator
from guardia.inventory import HostEnvironment
from guardia.render.rules_guide import render_rules_list, render_rules_markdown
from guardia.scanner import RULES

DOCS = Path(__file__).parent.parent / "docs"


def run(*argv: str, env: HostEnvironment) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


@pytest.mark.parametrize(("language", "name"), [("it", "REGOLE.md"), ("en", "RULES.md")])
def test_published_guide_is_up_to_date(language: str, name: str) -> None:
    published = (DOCS / name).read_text(encoding="utf-8")
    assert published == render_rules_markdown(Translator(language)), (
        f"docs/{name} is out of date: regenerate it with guardia rules --markdown"
    )


@pytest.mark.parametrize("language", ["it", "en"])
def test_guide_covers_every_rule_once(language: str) -> None:
    guide = render_rules_markdown(Translator(language))
    headings = re.findall(r"^### (G\d\d-\d{3}) ", guide, re.MULTILINE)
    assert headings == sorted(RULES)
    assert not re.search(r"\{\w+\}", guide)
    assert "rules." not in guide
    assert "guide." not in guide
    assert "category." not in guide
    assert "by Alexander Puglisi" in guide


def test_guide_escapes_markdown_from_rule_texts() -> None:
    guide = render_rules_markdown(Translator("it"))
    for line in guide.splitlines():
        if line.startswith(("**Perché.**", "**Come correggere.**", "### ")):
            body = line.split("** ", 1)[-1] if line.startswith("**") else line
            assert not re.search(r"(?<!\\)<", body), line


def test_list_shows_every_rule(env: HostEnvironment, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIA_LANG", "it")
    code, output = run("regole", env=env)
    assert code == 0
    for rule_id in RULES:
        assert rule_id in output
    assert output == render_rules_list(Translator("it"))


def test_single_rule_detail(env: HostEnvironment) -> None:
    code, output = run("rules", "g05-002", "--lang", "en", env=env)
    assert code == 0
    assert output.startswith("G05-002 · CRITICAL")
    assert "Why:" in output
    assert "How to fix:" in output
    assert not re.search(r"\{\w+\}", output)


def test_unknown_rule_is_a_usage_error(env: HostEnvironment) -> None:
    code, output = run("regole", "X99\x1b[31m", env=env)
    assert code == 2
    assert "\x1b" not in output


def test_markdown_written_to_file(env: HostEnvironment, tmp_path: Path) -> None:
    target = tmp_path / "RULES.md"
    code, _ = run("rules", "--markdown", "--lang", "en", "-o", str(target), env=env)
    assert code == 0
    assert target.read_text(encoding="utf-8") == render_rules_markdown(Translator("en"))
