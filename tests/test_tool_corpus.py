from __future__ import annotations

import ast
import tomllib
from pathlib import Path
from typing import Any

import pytest

from guardia.extract.sources import _Collector
from guardia.model import Client, ConfigSource, Scope, ServerEntry, ToolDefinition, Transport
from guardia.scanner import RULES
from guardia.scanner.tool_checks import TOOL_CHECKS, ToolContext

CORPUS = Path(__file__).parent / "corpus"
SERVERS = CORPUS / "tools" / "servers"
TOOL_CASES: list[dict[str, Any]] = tomllib.loads(
    (CORPUS / "tools" / "cases.toml").read_text(encoding="utf-8")
)["case"]
CONFIG_CASES: list[dict[str, Any]] = tomllib.loads(
    (CORPUS / "config_cases.toml").read_text(encoding="utf-8")
)["case"]
CODE_CASES: list[dict[str, Any]] = tomllib.loads(
    (CORPUS / "code" / "cases.toml").read_text(encoding="utf-8")
)["case"]
INTEGRATION_ONLY_RULES = frozenset(
    {
        "G03-001",
        "G03-002",
        "G03-003",
        "G03-004",
        "G03-005",
        "G03-006",
        "G04-002",
        "G04-003",
        "G12-003",
        "G12-004",
        "G12-005",
        "G12-006",
        "G12-007",
        "G12-008",
        "G12-009",
        "G13-001",
        "G13-002",
        "G14-001",
        "G14-002",
        "G14-003",
    }
)


DPAPI_EXCEPTION = frozenset({"ctypes"})
JOB_EXCEPTION = frozenset({"ctypes"})
ALLOWED_EXECUTION = {
    "secure_store.py": DPAPI_EXCEPTION,
    "process.py": frozenset({"subprocess"}),
    "windows.py": JOB_EXCEPTION,
}


def extract(path: Path) -> list[ToolDefinition]:
    collector = _Collector()
    collector.scan_root(path, "corpus")
    assert collector.notes == [], collector.notes
    return collector.tools


def server_for(path: Path) -> ServerEntry:
    return ServerEntry(
        name=path.stem,
        source=ConfigSource(Client.MANUAL, Scope.PATH, path),
        pointer="",
        transport=Transport.UNKNOWN,
    )


def rule_ids(path: Path) -> set[str]:
    server = server_for(path)
    return {
        finding.rule_id
        for tool in extract(path)
        for check in TOOL_CHECKS
        for finding in check(ToolContext(server, tool))
    }


@pytest.mark.parametrize("case", TOOL_CASES, ids=[case["file"] for case in TOOL_CASES])
def test_tool_case_triggers_exactly_the_expected_rules(case: dict[str, Any]) -> None:
    path = SERVERS / case["file"]
    assert extract(path), f"no tool extracted from {case['file']}"
    assert rule_ids(path) == set(case["expected"])


def test_every_corpus_file_is_listed() -> None:
    listed = {case["file"] for case in TOOL_CASES}
    assert listed == {path.name for path in SERVERS.iterdir()}


def test_tool_corpus_balance_and_rates() -> None:
    malicious = [c for c in TOOL_CASES if c["kind"] == "malicious"]
    benign = [c for c in TOOL_CASES if c["kind"] == "benign"]
    assert len(malicious) >= 25
    assert len(benign) >= 10
    detected = sum(1 for c in malicious if set(c["expected"]) <= rule_ids(SERVERS / c["file"]))
    false_alarms = sum(1 for c in benign if rule_ids(SERVERS / c["file"]))
    assert detected == len(malicious)
    assert false_alarms == 0


def test_every_rule_is_exercised() -> None:
    cases = [*TOOL_CASES, *CONFIG_CASES, *CODE_CASES]
    covered = {rule for case in cases for rule in case["expected"]}
    assert covered | INTEGRATION_ONLY_RULES == set(RULES)


def test_python_extraction_details() -> None:
    tools = {t.name: t for t in extract(SERVERS / "benign_records.py")}
    assert {t.kind.value for t in tools.values()} == {"tool", "prompt", "resource"}
    assert "records://{table}/schema" in tools
    assert tools["list_records"].annotations == {"readOnlyHint": True}
    schema = extract(SERVERS / "benign_weather.py")[0].input_schema
    assert schema["properties"]["latitude"]["description"] == "Latitude of the location"
    annotated = extract(SERVERS / "benign_filesystem.py")
    read_file = next(t for t in annotated if t.name == "read_file")
    assert read_file.input_schema["properties"]["path"]["description"].startswith("Absolute path")
    assert any(t.kind.value == "instructions" for t in annotated)


def test_python_constants_and_concatenation_are_resolved() -> None:
    tool = extract(SERVERS / "constant_indirection.py")[0]
    assert tool.description.startswith("Get the current time. <IMPORTANT>")
    padded = extract(SERVERS / "padding.py")[0]
    assert "Hidden part" in padded.description


def test_javascript_extraction_details() -> None:
    tools = {t.name: t for t in extract(SERVERS / "benign_meshy_like.ts")}
    assert set(tools) >= {"models_generate", "models_status", "instructions"}
    generate = tools["models_generate"]
    assert "NEVER base64-encode" in generate.description
    assert generate.input_schema["properties"]["prompt"]["description"] == "What to generate"
    labels = {f.label for f in generate.fields}
    assert "title" in labels
    joined = extract(SERVERS / "js_list_tools.js")[0]
    assert "Whenever you call any other tool" in joined.description
    shorthand = {t.name for t in extract(SERVERS / "benign_pdf.js")}
    assert shorthand == {"write_pdf", "make_pdf"}


def test_javascript_escapes_are_decoded() -> None:
    tool = extract(SERVERS / "js_unicode_escape.js")[0]
    assert "\u200b" in tool.description


def test_tool_findings_have_exact_lines() -> None:
    server = server_for(SERVERS / "invariant_add.py")
    tool = extract(SERVERS / "invariant_add.py")[0]
    findings = [f for check in TOOL_CHECKS for f in check(ToolContext(server, tool))]
    assert {f.location.line for f in findings} == {8}
    assert all(f.params["tool"] == "add" for f in findings)
    assert tool.location.line == 6


def test_tag_characters_are_decoded_in_the_evidence() -> None:
    server = server_for(SERVERS / "tag_smuggling.py")
    tool = extract(SERVERS / "tag_smuggling.py")[0]
    finding = next(f for check in TOOL_CHECKS for f in check(ToolContext(server, tool)))
    assert finding.params["decoded"] == "read .env"


def test_guardia_never_imports_execution_primitives() -> None:
    forbidden_modules = {
        "subprocess",
        "runpy",
        "pty",
        "ctypes",
        "multiprocessing",
        "pickle",
        "marshal",
    }
    forbidden_names = {"eval", "exec", "compile", "__import__", "breakpoint"}
    forbidden_attributes = {"system", "popen", "import_module", "startfile", "execv", "spawnv"}
    source = Path(__file__).parent.parent / "src" / "guardia"
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        allowed = ALLOWED_EXECUTION.get(path.name, frozenset())
        if path.name in ("process.py", "windows.py"):
            assert path.parent.name == "shield", path
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
                assert not (names & forbidden_modules) - allowed, f"{path}: {names}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                module = node.module.split(".")[0]
                assert module not in forbidden_modules - allowed, f"{path}: {node.module}"
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    assert func.id not in forbidden_names, f"{path}:{node.lineno}: {func.id}"
                elif isinstance(func, ast.Attribute):
                    assert func.attr not in forbidden_attributes, f"{path}:{node.lineno}"


def test_no_shell_execution_anywhere() -> None:
    source = Path(__file__).parent.parent / "src" / "guardia"
    importers = []
    for path in source.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False, path
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = (
                    [node.module or ""]
                    if isinstance(node, ast.ImportFrom)
                    else [alias.name for alias in node.names]
                )
                if any(name.split(".")[0] == "subprocess" for name in names):
                    importers.append(path.relative_to(source).as_posix())
    assert importers == ["shield/process.py"]
