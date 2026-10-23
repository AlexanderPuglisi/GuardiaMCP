from __future__ import annotations

import re
from pathlib import Path

import pytest

from guardia.shield.rules import ACTION_NAMES, PHASE_NAMES, all_keys, parse_rules

DOCS = Path(__file__).parent.parent / "docs"
GUIDES = ("SCUDO.md", "SHIELD.md")
TOML_BLOCK = re.compile(r"```toml\n(.*?)```", re.DOTALL)
HOME = "c:/users/demo"


def guide(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", GUIDES)
def test_guides_document_every_key_action_and_phase(name: str) -> None:
    text = guide(name)
    missing = [key for key in [*all_keys(), *ACTION_NAMES, *PHASE_NAMES] if f"`{key}`" not in text]
    assert missing == []


@pytest.mark.parametrize("name", GUIDES)
def test_every_toml_example_in_the_guides_is_valid(name: str) -> None:
    blocks = TOML_BLOCK.findall(guide(name))
    assert len(blocks) >= 9
    for block in blocks:
        source = (
            block if block.lstrip().startswith(("version", "versione")) else "version = 1\n" + block
        )
        result = parse_rules(source, HOME)
        assert result.ruleset is not None, (block, [(i.code, i.line) for i in result.issues])
        assert result.ruleset.rules


@pytest.mark.parametrize("name", GUIDES)
def test_guides_link_each_other_and_security(name: str) -> None:
    text = guide(name)
    assert "SECURITY.md" in text
    assert ("SHIELD.md" if name == "SCUDO.md" else "SCUDO.md") in text
    assert "by Alexander Puglisi" in text
