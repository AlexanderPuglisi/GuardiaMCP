from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from guardia.model import (
    Client,
    ConfigSource,
    Finding,
    Inventory,
    Location,
    Scope,
    ServerEntry,
    Severity,
    SourceRecord,
    SourceStatus,
    Transport,
    canonical_json,
    frozen_mapping,
    json_pointer,
)

SOURCE = ConfigSource(Client.CLAUDE_DESKTOP, Scope.USER, Path("config.json"))


def make_server(raw: dict[str, object], **overrides: Any) -> ServerEntry:
    fields: dict[str, Any] = {
        "name": "demo",
        "source": SOURCE,
        "pointer": "/mcpServers/demo",
        "transport": Transport.STDIO,
        "command": "npx",
        "args": ("-y", "demo-server"),
        "env": frozen_mapping({"DEMO_TOKEN": "super-secret-value"}),
        "headers": frozen_mapping({"Authorization": "Bearer hidden-header-value"}),
        "raw": frozen_mapping(raw),
    }
    fields.update(overrides)
    return ServerEntry(**fields)


def test_fingerprint_does_not_depend_on_key_order() -> None:
    first = make_server({"command": "npx", "args": ["a"], "env": {"X": "1", "Y": "2"}})
    second = make_server({"env": {"Y": "2", "X": "1"}, "args": ["a"], "command": "npx"})
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64


def test_fingerprint_changes_when_anything_changes() -> None:
    first = make_server({"command": "npx", "args": ["a"]})
    second = make_server({"command": "npx", "args": ["b"]})
    assert first.fingerprint != second.fingerprint


def test_serialization_never_contains_secret_values() -> None:
    server = make_server({"command": "npx"})
    text = json.dumps(server.to_dict())
    assert "super-secret-value" not in text
    assert "hidden-header-value" not in text
    assert server.to_dict()["env_keys"] == ["DEMO_TOKEN"]
    assert server.to_dict()["header_keys"] == ["Authorization"]


def test_repr_never_contains_secret_values() -> None:
    server = make_server({"command": "npx"})
    assert "super-secret-value" not in repr(server)


def test_server_entry_is_immutable() -> None:
    server = make_server({"command": "npx"})
    with pytest.raises(AttributeError):
        server.__setattr__("name", "other")
    with pytest.raises(TypeError):
        cast(dict[str, str], server.env)["DEMO_TOKEN"] = "x"


def test_display_target_for_stdio_and_http() -> None:
    stdio = make_server({}, args=("--api-key", "abc"))
    http = make_server(
        {}, transport=Transport.HTTP, command=None, args=(), url="https://h.example/mcp?token=t"
    )
    assert stdio.display_target() == "npx --api-key [REDACTED]"
    assert http.display_target() == "https://h.example/mcp?token=[REDACTED]"


def test_json_pointer_escapes_special_characters() -> None:
    assert json_pointer("mcpServers", "a/b~c") == "/mcpServers/a~1b~0c"


def test_canonical_json_is_stable_and_rejects_nan() -> None:
    assert canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_json({"a": float("nan")})


def test_severity_is_ordered() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.HIGH.label == "high"


def test_finding_serializes() -> None:
    finding = Finding(
        rule_id="G01-001",
        severity=Severity.HIGH,
        location=Location(Path("server.py"), "/tools/0/description", 12),
        params=frozen_mapping({"field": "description"}),
    )
    data = finding.to_dict()
    assert data["category"] == "G01"
    assert data["severity"] == "high"
    assert data["location"]["line"] == 12
    assert data["params"] == {"field": "description"}


def test_locate_falls_back_to_the_nearest_known_line() -> None:
    server = make_server(
        {}, lines=frozen_mapping({"/mcpServers/demo": 3, "/mcpServers/demo/args": 5})
    )
    assert server.locate("/mcpServers/demo/args/1").line == 5
    assert server.locate("/mcpServers/demo/env/X").line == 3
    assert server.locate("/mcpServers/demo/env/X").pointer == "/mcpServers/demo/env/X"
    assert make_server({}).location.line is None


def test_inventory_serializes_with_tool_metadata() -> None:
    inventory = Inventory(
        servers=(make_server({"command": "npx"}),),
        sources=(SourceRecord(SOURCE, SourceStatus.LOADED, server_count=1),),
    )
    data = inventory.to_dict()
    assert data["tool"] == "guardia-mcp"
    assert data["sources"][0]["status"] == "loaded"
    assert len(inventory.loaded_sources) == 1
    assert inventory.failed_sources == ()
