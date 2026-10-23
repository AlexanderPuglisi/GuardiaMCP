from __future__ import annotations

import ast
from pathlib import Path

from guardia.extract.strings import classify
from guardia.model import CodeSignal, Location, SignalKind

PROCESS_CALLS = frozenset(
    {
        ("subprocess", name)
        for name in (
            "run",
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        )
    }
    | {
        ("os", name)
        for name in (
            "system",
            "popen",
            "startfile",
            "posix_spawn",
            "posix_spawnp",
            "execv",
            "execve",
            "execl",
            "execle",
            "execlp",
            "execvp",
            "execvpe",
            "spawnl",
            "spawnv",
            "spawnve",
        )
    }
    | {
        ("asyncio", "create_subprocess_exec"),
        ("asyncio", "create_subprocess_shell"),
        ("pty", "spawn"),
    }
)
SHELL_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("subprocess", "getoutput"),
        ("subprocess", "getstatusoutput"),
        ("asyncio", "create_subprocess_shell"),
    }
)
NETWORK_MODULES = frozenset(
    {
        "requests",
        "httpx",
        "urllib.request",
        "urllib3",
        "aiohttp",
        "socket",
        "http.client",
        "smtplib",
        "ftplib",
        "websocket",
        "websockets",
        "paramiko",
        "pycurl",
    }
)
DECODER_NAMES = frozenset(
    {
        "b64decode",
        "b32decode",
        "b85decode",
        "a85decode",
        "urlsafe_b64decode",
        "standard_b64decode",
        "decodebytes",
        "fromhex",
        "unhexlify",
        "decompress",
        "loads",
    }
)
EVAL_NAMES = frozenset({"eval", "exec", "compile", "__import__"})
MAX_SIGNALS_PER_KIND = 20


class _Aliases:
    def __init__(self, tree: ast.Module) -> None:
        self.modules: dict[str, str] = {}
        self.names: dict[str, tuple[str, str]] = {}
        self.imported: list[tuple[str, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.modules[alias.asname or alias.name.split(".")[0]] = alias.name
                    self.imported.append((alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    full = f"{node.module}.{alias.name}"
                    self.names[alias.asname or alias.name] = (node.module, alias.name)
                    self.modules.setdefault(alias.asname or alias.name, full)
                    self.imported.append((full, node.lineno))
                self.imported.append((node.module, node.lineno))

    def resolve(self, func: ast.AST) -> tuple[str, str] | None:
        if isinstance(func, ast.Attribute):
            owner = func.value
            if isinstance(owner, ast.Name):
                module = self.modules.get(owner.id, owner.id)
                return module.split(".")[-1] if module != "os.path" else module, func.attr
            if isinstance(owner, ast.Attribute):
                return owner.attr, func.attr
            return "", func.attr
        if isinstance(func, ast.Name):
            return self.names.get(func.id, ("", func.id))
        return None


def _docstring_nodes(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _is_constant_text(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str | bytes)


def _contains_decoder(node: ast.AST, aliases: _Aliases) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            resolved = aliases.resolve(child.func)
            if resolved is None:
                continue
            owner, name = resolved
            if name in DECODER_NAMES or (owner == "codecs" and name == "decode"):
                return True
            if name == "chr" or (
                name == "join"
                and any(
                    isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "chr"
                    for c in ast.walk(child)
                )
            ):
                return True
    return False


def _shell_true(call: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in call.keywords
    )


def _environ(node: ast.AST, aliases: _Aliases) -> bool:
    if (
        isinstance(node, ast.Call)
        and node.args
        and isinstance(node.func, ast.Name)
        and node.func.id in ("dict", "list", "str")
    ):
        return _environ(node.args[0], aliases)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("copy", "items")
    ):
        return _environ(node.func.value, aliases)
    if isinstance(node, ast.Dict) and any(key is None for key in node.keys):
        return any(_environ(value, aliases) for value in node.values)
    if isinstance(node, ast.Attribute) and node.attr == "environ":
        return (
            isinstance(node.value, ast.Name)
            and aliases.modules.get(node.value.id, node.value.id) == "os"
        )
    return isinstance(node, ast.Name) and aliases.names.get(node.id) == ("os", "environ")


class _Signals:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.items: list[CodeSignal] = []
        self.counts: dict[SignalKind, int] = {}

    def add(self, kind: SignalKind, line: int | None, evidence: str = "", detail: str = "") -> None:
        count = self.counts.get(kind, 0)
        limit = (
            1
            if kind in (SignalKind.PROCESS, SignalKind.NETWORK, SignalKind.FILE_READ)
            else MAX_SIGNALS_PER_KIND
        )
        if count >= limit:
            return
        self.counts[kind] = count + 1
        self.items.append(CodeSignal(kind, Location(self.path, "", line), evidence[:160], detail))


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (ValueError, RecursionError):
        return ""


def python_signals(path: Path, tree: ast.Module) -> list[CodeSignal]:
    aliases = _Aliases(tree)
    signals = _Signals(path)
    for module, line in aliases.imported:
        if module in NETWORK_MODULES or module.split(".")[0] in NETWORK_MODULES:
            signals.add(SignalKind.NETWORK, line, module)
    docstrings = _docstring_nodes(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _call_signals(node, aliases, signals)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
        ):
            for kind, evidence, detail in classify(node.value):
                signals.add(kind, node.lineno, evidence, detail)
    return signals.items


def _call_signals(node: ast.Call, aliases: _Aliases, signals: _Signals) -> None:
    resolved = aliases.resolve(node.func)
    if resolved is None:
        return
    owner, name = resolved
    line = node.lineno
    first = node.args[0] if node.args else None
    if (owner, name) in PROCESS_CALLS:
        signals.add(SignalKind.PROCESS, line, _unparse(node))
        shell = (owner, name) in SHELL_CALLS or _shell_true(node)
        if shell and first is not None and not _is_constant_text(first):
            signals.add(SignalKind.SHELL_STRING, line, _unparse(node))
    elif isinstance(node.func, ast.Name) and name in EVAL_NAMES and first is not None:
        if _contains_decoder(first, aliases):
            signals.add(SignalKind.DECODE_EXEC, line, _unparse(node))
        elif not _is_constant_text(first):
            signals.add(SignalKind.DYNAMIC_EVAL, line, _unparse(node))
    elif owner in ("pickle", "marshal", "dill") and name == "loads" and first is not None:
        if _contains_decoder(first, aliases):
            signals.add(SignalKind.DECODE_EXEC, line, _unparse(node))
    elif name in ("open", "read_text", "read_bytes"):
        signals.add(SignalKind.FILE_READ, line, _unparse(node))
    elif (owner, name) in (("json", "dumps"), ("", "str"), ("", "repr")) and first is not None:
        if _environ(first, aliases):
            signals.add(SignalKind.ENV_DUMP, line, _unparse(node))
