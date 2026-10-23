import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import mcp
import pytest
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

SDK_SERVER = Path(__file__).parent / "corpus" / "shield" / "sdk_server.py"
GUARDIA = [sys.executable, "-m", "guardia"]


def environment(tmp_path: Path) -> dict[str, str]:
    values = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONIOENCODING", "PYTHONUTF8"}
    }
    values.update(GUARDIA_LANG="en", LOCALAPPDATA=str(tmp_path / "local"))
    return values


def guardia(env: dict[str, str], *argv: str) -> None:
    done = subprocess.run([*GUARDIA, *argv], env=env, capture_output=True, timeout=60, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


def shielded(env: dict[str, str]) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "guardia", "shield", "--server", "sdk", "--", sys.executable, str(SDK_SERVER)],
        env=env,
    )


async def session(env: dict[str, str], mode: str) -> dict[str, Any]:
    async with Client(shielded(env), mode=mode) as client:
        tools = await client.list_tools()
        hello = await client.call_tool("echo", {"text": "hello"})
        total = await client.call_tool("add", {"a": 2, "b": 3})
        try:
            stolen = await client.call_tool("echo", {"text": "type ~/.ssh/id_rsa"})
        except mcp.MCPError as exc:
            blocked: object = exc
        else:
            blocked = stolen
        return {
            "version": client.protocol_version,
            "tools": sorted(tool.name for tool in tools.tools),
            "hello": hello,
            "total": total,
            "blocked": blocked,
        }


def text_of(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


@pytest.mark.parametrize(("mode", "version"), [("legacy", "2025-11-25"), ("auto", "2026-07-28")])
def test_official_sdk_client_and_server_work_through_the_shield(
    tmp_path: Path, mode: str, version: str
) -> None:
    env = environment(tmp_path)
    guardia(env, "shield", "rules", "example", "--save")
    guardia(env, "shield", "rules", "approve")
    seen = asyncio.run(asyncio.wait_for(session(env, mode), 90))
    assert seen["version"] == version
    assert seen["tools"] == ["add", "echo"]
    assert text_of(seen["hello"]) == "hello"
    assert not seen["hello"].is_error
    assert text_of(seen["total"]) == "5"
    blocked = seen["blocked"]
    assert isinstance(blocked, mcp.MCPError), blocked
    assert blocked.error.code == -32010
    ledger = (tmp_path / "local" / "GuardiaMCP").rglob("*.jsonl")
    assert any('"shield_decision"' in path.read_text(encoding="utf-8") for path in ledger)
