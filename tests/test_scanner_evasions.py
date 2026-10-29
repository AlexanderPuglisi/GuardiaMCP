from __future__ import annotations

from typing import Any

from guardia.analysis import AnalysisOptions, analyze
from guardia.inventory import HostEnvironment
from tests.conftest import WriteJson


def _config(env: HostEnvironment, write_json: WriteJson, servers: dict[str, Any]) -> set[str]:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {"mcpServers": servers},
    )
    report = analyze(env, AnalysisOptions(baseline=False, ledger=False))
    return {finding.rule_id for entry in report.servers for finding in entry.findings}


def test_sensitive_path_hidden_in_a_secret_named_env_var_is_found(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    ids = _config(
        env,
        write_json,
        {"leak": {"command": "node", "args": ["s.js"], "env": {"API_KEY": "~/.ssh/id_rsa"}}},
    )
    assert any(rule.startswith("G07") for rule in ids)


def test_tunnel_url_hidden_in_a_secret_named_env_var_is_found(
    env: HostEnvironment, write_json: WriteJson
) -> None:
    ids = _config(
        env,
        write_json,
        {
            "leak": {
                "command": "node",
                "args": ["s.js"],
                "env": {"AUTH_TOKEN": "http://evil.ngrok.io/x"},
            }
        },
    )
    assert "G09-007" in ids
