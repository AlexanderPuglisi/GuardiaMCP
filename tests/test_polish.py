from __future__ import annotations

import codecs
import io
import json
import sys
from pathlib import Path

import pytest

from guardia.analysis import AnalysisOptions, analyze
from guardia.app.api import GuardiaApi, GuardiaUiError
from guardia.app.settings import SettingsStore
from guardia.app.viewmodel import report_view
from guardia.cli import main
from guardia.i18n import Translator
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR
from guardia.shield.activation import ActivationStore, candidates
from tests.conftest import WriteJson, WriteText


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def help_text(*argv: str) -> str:
    out = io.StringIO()
    previous = sys.stdout
    sys.stdout = out
    try:
        with pytest.raises(SystemExit):
            main(list(argv))
    finally:
        sys.stdout = previous
    return out.getvalue()


def test_help_is_fully_translated_and_hides_internal_commands() -> None:
    italian = help_text("scudo", "--help", "--lingua", "it")
    assert "==SUPPRESS==" not in italian
    assert "conferma" not in italian.split("ricollega")[0].split("{")[-1]
    assert italian.startswith("uso:")
    assert "opzioni:" in italian
    assert "mostra questo aiuto ed esci" in italian
    english = help_text("shield", "--help", "--lang", "en")
    assert "==SUPPRESS==" not in english
    assert english.startswith("usage:")
    assert "show this help and exit" in english
    assert "relink" in english


def test_output_file_errors_are_reported_without_a_traceback(
    env: HostEnvironment, tmp_path: Path
) -> None:
    folder = tmp_path / "out"
    folder.mkdir()
    code, output = run_cli(env, "rules", "--lang", "en", "-o", str(folder))
    assert code == 2
    assert "Cannot write" in output
    target = tmp_path / "rules.txt"
    code, _ = run_cli(env, "rules", "--lang", "en", "-o", str(target))
    assert code == 0
    assert b"\r\n" not in target.read_bytes()


def test_ledger_show_prints_counts_only_for_scans(env: HostEnvironment) -> None:
    ledger = Ledger(env.data_dir)
    ledger.append("scan", {"summary": {"critical": 1, "high": 0, "medium": 0, "low": 0}})
    ledger.append("rules_approved", {"sha256": "0" * 64, "rules": 5, "default": "allow"})
    ledger.append("settings_changed", {"setting": "glow", "before": True, "after": False})
    _, output = run_cli(env, "ledger", "show", "--last", "5", "--lang", "en")
    lines = [line for line in output.splitlines() if line[:2] in ("1.", "2.", "3.")]
    assert "CRITICAL 1" in lines[0]
    assert lines[1].endswith("rules_approved · rules: 5")
    assert "CRITICAL" not in lines[2]
    assert not lines[2].endswith("·")


def test_protect_keeps_the_original_file_style(env: HostEnvironment) -> None:
    path = env.app_config / "Claude" / "claude_desktop_config.json"
    path.parent.mkdir(parents=True)
    document = {"mcpServers": {"github": {"command": "npx", "args": ["-y", "x"]}}, "theme": "città"}
    text = json.dumps(document, indent=4, ensure_ascii=False).replace("\n", "\r\n") + "\r\n"
    path.write_bytes(codecs.BOM_UTF8 + text.encode("utf-8"))
    store = ActivationStore(env.data_dir)
    servers = [c.server for c in candidates(discover(env, DiscoveryOptions(skills=False)))]
    store.enable(servers, ["C:/Tools/guardia.exe"])
    data = path.read_bytes()
    assert data.startswith(codecs.BOM_UTF8)
    assert b"\r\n" in data
    assert b"\n" not in data.replace(b"\r\n", b"")
    assert b'\r\n    "mcpServers": {' in data
    assert "città".encode() in data
    store.disable(["github"])
    assert path.read_bytes() == codecs.BOM_UTF8 + text.encode("utf-8")


def test_clean_entries_are_ok_and_coverage_gaps_are_flagged(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {"remote": {"url": "https://example.test/mcp"}}},
    )
    view = report_view(analyze(env, AnalysisOptions()), Translator("it"), 0.1)
    entry = view["entries"][0]
    assert view["coverage_gaps"] is True
    assert "--percorso" not in " ".join(view["coverage"])
    assert "--percorso" not in entry["coverage"]
    clean = [e for e in view["entries"] if not e["findings"]]
    for item in clean:
        assert (item["risk"], item["risk_label"]) == ("ok", "OK")


def test_broken_client_config_is_a_medium_problem(
    env: HostEnvironment, write_text: WriteText
) -> None:
    write_text(
        env.app_config / "Claude" / "claude_desktop_config.json", '{"mcpServers": {"a": {},}}'
    )
    view = report_view(analyze(env, AnalysisOptions()), Translator("en"), 0.1)
    broken = [f for f in view["file_findings"] if f["rule_id"] == "G12-006"]
    assert [f["severity"] for f in broken] == ["medium"]
    assert broken[0] in view["priority"]


def test_export_errors_are_translated(env: HostEnvironment, tmp_path: Path) -> None:
    folder = tmp_path / "is-a-folder"
    folder.mkdir()
    api = GuardiaApi(
        env, SettingsStore(env.data_dir), save_dialog=lambda _: str(folder), protector=RAW_PROTECTOR
    )
    api.scan()
    with pytest.raises(GuardiaUiError, match="Non riesco a salvare"):
        api.export("html")


def test_ledger_view_describes_shield_events(env: HostEnvironment) -> None:
    ledger = Ledger(env.data_dir, RAW_PROTECTOR)
    ledger.append(
        "shield_decision",
        {"server": "notes", "action": "block", "tool": "read_note", "answer": "block"},
    )
    ledger.append("rules_approved", {"sha256": "0" * 64, "rules": 3, "default": "allow"})
    api = GuardiaApi(env, SettingsStore(env.data_dir), protector=RAW_PROTECTOR)
    events = api.ledger(5)["events"]
    assert events[0]["details"] == "regole: 3"
    assert events[1]["details"].startswith("notes · blocca · read_note")
