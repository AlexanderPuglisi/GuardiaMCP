from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from guardia.extract.sources import _Collector
from guardia.model import (
    Client,
    ConfigSource,
    Finding,
    Scope,
    ServerEntry,
    SignalKind,
    ToolCollection,
    Transport,
)
from guardia.scanner.code_checks import code_findings

CODE = Path(__file__).parent / "corpus" / "code"
CASES: list[dict[str, Any]] = tomllib.loads((CODE / "cases.toml").read_text(encoding="utf-8"))[
    "case"
]


def analyze(directory: Path, origin: str = "corpus") -> tuple[ToolCollection, list[Finding]]:
    collector = _Collector()
    collector.scan_root(directory, origin)
    assert collector.notes == [], collector.notes
    collection = ToolCollection(
        tools=tuple(collector.tools),
        origins=tuple(collector.origins),
        signals=tuple(collector.signals),
    )
    server = ServerEntry(
        name=directory.name,
        source=ConfigSource(Client.MANUAL, Scope.PATH, directory),
        pointer="",
        transport=Transport.UNKNOWN,
    )
    return collection, list(code_findings(server, collection))


@pytest.mark.parametrize("case", CASES, ids=[case["dir"] for case in CASES])
def test_code_case_triggers_exactly_the_expected_rules(case: dict[str, Any]) -> None:
    _, findings = analyze(CODE / case["dir"], case.get("origin", "corpus"))
    assert {f.rule_id for f in findings} == set(case["expected"])
    if "severity" in case:
        assert max(f.severity for f in findings).label == case["severity"]


def test_every_code_case_directory_is_listed() -> None:
    listed = {case["dir"] for case in CASES}
    on_disk = {path.name for path in CODE.iterdir() if path.is_dir()}
    assert listed == on_disk


def test_code_corpus_rates() -> None:
    malicious = [c for c in CASES if c["kind"] == "malicious"]
    benign = [c for c in CASES if c["kind"] == "benign"]
    assert len(malicious) >= 20
    assert len(benign) >= 4
    for case in benign:
        _, findings = analyze(CODE / case["dir"], case.get("origin", "corpus"))
        assert findings == [], case["dir"]


def test_capabilities_are_reported_without_findings() -> None:
    collection, findings = analyze(CODE / "benign_py_server")
    assert findings == []
    assert set(collection.capabilities) == {
        SignalKind.PROCESS,
        SignalKind.NETWORK,
        SignalKind.FILE_READ,
    }
    js_collection, _ = analyze(CODE / "benign_js_server", "path")
    assert SignalKind.PROCESS in js_collection.capabilities
    assert SignalKind.NETWORK in js_collection.capabilities


def test_code_findings_point_to_the_exact_line() -> None:
    _, findings = analyze(CODE / "py_ssh_exfil")
    finding = findings[0]
    assert finding.location.line == 7
    assert finding.location.path.name == "server.py"
    _, dependency = analyze(CODE / "npm_lookalike")
    assert dependency[0].location.line == 5
    assert dependency[0].params["detail"] == "express"


def test_secrets_in_code_are_never_shown_in_clear() -> None:
    _, findings = analyze(CODE / "js_secret")
    assert "abc123def456" not in findings[0].evidence
    assert "[REDACTED]" in findings[0].evidence


def test_installed_dependency_tree_is_checked(tmp_path: Path) -> None:
    modules = tmp_path / "_npx" / "abc" / "node_modules"
    server = modules / "@acme" / "server"
    server.mkdir(parents=True)
    (server / "package.json").write_text(
        '{"name": "@acme/server", "version": "1.0.0"}', encoding="utf-8"
    )
    dependency = modules / "native-thing"
    dependency.mkdir(parents=True)
    (dependency / "package.json").write_text(
        '{"name": "native-thing", "scripts": {"install": "node build.js"}}', encoding="utf-8"
    )
    lookalike = modules / "lodahs"
    lookalike.mkdir()
    (lookalike / "package.json").write_text('{"name": "lodahs"}', encoding="utf-8")
    collector = _Collector()
    collector.scan_dependencies(server, "npm-cache")
    kinds = {signal.kind for signal in collector.signals}
    assert kinds == {SignalKind.INSTALL_SCRIPT, SignalKind.DEPENDENCY_LOOKALIKE}
