from __future__ import annotations

import ast
from pathlib import Path

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
            assert path.relative_to(SOURCE).as_posix() == "app/main.py", path
