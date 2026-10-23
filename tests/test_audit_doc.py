from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
CITED = re.compile(r"`(tests/\w+\.py)::(\w+)`")
FILES = re.compile(r"`(src/guardia/[\w/]+\.(?:py|js))`")


def test_every_test_cited_by_the_audit_guide_exists() -> None:
    text = (ROOT / "AUDIT.md").read_text(encoding="utf-8")
    cited = set(CITED.findall(text))
    assert len(cited) >= 10
    for file, name in cited:
        tree = ast.parse((ROOT / file).read_text(encoding="utf-8"))
        names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        assert name in names, f"{file}::{name}"


def test_every_source_file_cited_by_the_audit_guide_exists() -> None:
    text = (ROOT / "AUDIT.md").read_text(encoding="utf-8")
    for path in set(FILES.findall(text)):
        assert (ROOT / path).is_file(), path
