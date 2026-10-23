from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any

import pytest

from guardia.analysis import AnalysisOptions, analyze
from guardia.inventory import HostEnvironment
from guardia.inventory.parsers import _resolve_inside
from tests.conftest import WriteJson

SOURCE = Path(__file__).parent.parent / "src" / "guardia"
NETWORK_MODULES = frozenset(
    {
        "socket",
        "ssl",
        "http",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "telnetlib",
        "xmlrpc",
        "socketserver",
        "asyncio",
        "webbrowser",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
    }
)
ALLOWED_URLLIB = frozenset({"urllib.parse"})


def imported_modules(path: Path) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def test_guardia_has_no_network_code() -> None:
    for path in SOURCE.rglob("*.py"):
        for module in imported_modules(path):
            root = module.split(".")[0]
            assert root not in NETWORK_MODULES, f"{path}: {module}"
            if root == "urllib":
                assert module in ALLOWED_URLLIB, f"{path}: {module}"


def test_cli_has_no_runtime_dependencies() -> None:
    text = (SOURCE.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert "dependencies = []" in text


def test_only_the_app_imports_pywebview() -> None:
    for path in SOURCE.rglob("*.py"):
        if "webview" in {m.split(".")[0] for m in imported_modules(path)}:
            assert path.relative_to(SOURCE).as_posix() in {"app/main.py", "app/confirm.py"}, path


def test_scan_never_touches_network_paths_from_configs(
    env: HostEnvironment, write_json: WriteJson, monkeypatch: pytest.MonkeyPatch
) -> None:
    share = r"\\guardia-test.invalid\share"
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {
            "mcpServers": {
                "remote-code": {"command": "node", "args": [share + r"\server.js"]},
                "remote-cwd": {"command": "node", "args": ["server.js"], "cwd": share},
                "remote-dir": {"command": "uv", "args": ["--directory", share, "run", "x"]},
            }
        },
    )
    touched: list[str] = []
    real_stat = os.stat
    real_scandir = os.scandir
    real_realpath = os.path.realpath

    def network(path: object) -> bool:
        text = os.fspath(path) if isinstance(path, str | os.PathLike) else ""
        return str(text).replace("/", "\\").startswith("\\\\")

    def stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if network(path):
            touched.append(str(path))
            raise OSError("network path")
        return real_stat(path, *args, **kwargs)

    def scandir(path: Any = ".") -> Any:
        if network(path):
            touched.append(str(path))
            raise OSError("network path")
        return real_scandir(path)

    def realpath(path: Any, *args: Any, **kwargs: Any) -> Any:
        if network(path):
            touched.append(str(path))
            raise OSError("network path")
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os.path, "realpath", realpath)
    analyze(env, AnalysisOptions(tools=True))
    assert touched == []


def test_plugin_references_never_resolve_network_paths(tmp_path: Path) -> None:
    assert _resolve_inside(tmp_path, r"\\guardia-test.invalid\share\mcp.json") is None
    assert _resolve_inside(tmp_path, "//guardia-test.invalid/share/mcp.json") is None
    assert _resolve_inside(tmp_path, "a\x00b") is None
