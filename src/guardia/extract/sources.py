from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePath

from guardia.extract.common import ExtractionError, dedupe
from guardia.extract.dependencies import dependency_signals, installed_tree_signals
from guardia.extract.documents import tools_from_json_file
from guardia.extract.js_source import analyze_javascript
from guardia.extract.python_source import analyze_python
from guardia.extract.skill_source import shell_script_signals, skill_definition, skill_signals
from guardia.inventory.environment import HostEnvironment
from guardia.inventory.locations import child_dirs, real_dirs
from guardia.inventory.skills import parse_skill
from guardia.model import (
    CodeSignal,
    Location,
    Scope,
    ServerEntry,
    SignalKind,
    ToolCollection,
    ToolDefinition,
    ToolGap,
    Transport,
)
from guardia.safeio import SafeReadError, is_network_path, parse_json, read_text
from guardia.scanner.checks import effective_command
from guardia.scanner.commandline import parse_runner, program_name

PYTHON_SUFFIXES = frozenset({".py"})
JS_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"})
CODE_SUFFIXES = PYTHON_SUFFIXES | JS_SUFFIXES
SKIPPED_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
        "test",
        "tests",
        "__tests__",
        "spec",
        "examples",
        "coverage",
        ".mypy_cache",
        ".pytest_cache",
    }
)
DIRECTORY_FLAGS = frozenset({"--directory", "--cwd", "--prefix", "--project"})
WORKSPACE_PLACEHOLDERS = ("${workspaceFolder}", "${workspaceRoot}", "${workspaceFolderBasename}")
COMMAND_WORD = re.compile(r'"([^"]*)"|(\S+)')
NPM_SHIM_TARGET = re.compile(r"node_modules[\\/]((?:@[^\\/\"\s]+[\\/])?[^\\/\"\s]+)")
SHIM_SUFFIXES = ("", ".cmd", ".ps1")
MAX_SHIM_BYTES = 64 * 1024
PYTHON_PROGRAMS = frozenset({"python", "python3", "py", "pythonw"})
SCRIPT_RUNNERS = frozenset(
    {
        "npx",
        "uvx",
        "node",
        "python",
        "python3",
        "py",
        "uv",
        "bunx",
        "pnpm",
        "deno",
        "bun",
        "cmd",
        "docker",
    }
)
KNOWN_LAUNCHERS = SCRIPT_RUNNERS | {
    "pythonw",
    "pnpx",
    "yarn",
    "npm",
    "powershell",
    "pwsh",
    "podman",
    "wsl",
    "pipx",
}
MAX_FILES = 400
MAX_FILE_BYTES = 3 * 1024 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
MAX_DEPTH = 8
MAX_CACHE_DIRS = 3000
SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"})
SCRIPT_SUFFIXES = CODE_SUFFIXES | SHELL_SUFFIXES
SKILL_SCRIPT_DEPTH = 4
MAX_SKILL_SCRIPTS = 200
MAX_SKILL_BYTES = 2 * 1024 * 1024
INSTALL_TIME_RISKS = frozenset(
    {SignalKind.PROCESS, SignalKind.NETWORK, SignalKind.DECODE_EXEC, SignalKind.DYNAMIC_EVAL}
)


@dataclass(slots=True)
class _Collector:
    tools: list[ToolDefinition] = field(default_factory=list)
    origins: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    signals: list[CodeSignal] = field(default_factory=list)
    files: int = 0
    total_bytes: int = 0
    seen: set[str] = field(default_factory=set)
    roots_seen: set[str] = field(default_factory=set)

    def note(self, code: str, detail: str) -> None:
        entry = f"{code}:{detail}"
        if entry not in self.notes:
            self.notes.append(entry)

    def scan_file(self, path: Path) -> None:
        key = os.path.normcase(str(path))
        if key in self.seen:
            return
        self.seen.add(key)
        if self.files >= MAX_FILES or self.total_bytes >= MAX_TOTAL_BYTES:
            self.note("limit", str(path.parent))
            return
        try:
            text = read_text(path, MAX_FILE_BYTES)
        except SafeReadError as exc:
            self.note("unreadable", f"{path} ({exc.code.value})")
            return
        self.files += 1
        self.total_bytes += len(text)
        suffix = path.suffix.lower()
        try:
            if suffix in PYTHON_SUFFIXES:
                tools, signals = analyze_python(path, text)
            elif suffix in JS_SUFFIXES:
                tools, signals = analyze_javascript(path, text)
            else:
                return
        except ExtractionError as exc:
            self.note("unparsable", f"{path} ({exc})")
            return
        self.tools.extend(tools)
        self.signals.extend(signals)
        if path.name.lower() == "setup.py":
            risky = sorted({s.kind.value for s in signals if s.kind in INSTALL_TIME_RISKS})
            if risky:
                self.signals.append(
                    CodeSignal(
                        SignalKind.SETUP_EXEC, Location(path, "", 1), str(path), ", ".join(risky)
                    )
                )

    def scan_manifest(self, path: Path, origin: str) -> None:
        try:
            self.tools.extend(tools_from_json_file(path, origin))
            self.origins.append(f"{origin}:{path}")
        except SafeReadError as exc:
            self.note("unreadable", f"{path} ({exc.code.value})")

    def scan_root(self, root: Path, origin: str) -> None:
        before = self.files
        if root.is_file():
            if root.suffix.lower() == ".json":
                self.scan_manifest(root, "snapshot")
                return
            self.scan_file(root)
        else:
            manifest = root / "manifest.json"
            if manifest.is_file() and f"manifest:{manifest}" not in self.origins:
                self.scan_manifest(manifest, "manifest")
            for path in code_files(root):
                self.scan_file(path)
            self.scan_dependencies(root, origin)
        if self.files > before:
            self.origins.append(f"{origin}:{root}")

    def scan_dependencies(self, root: Path, origin: str) -> None:
        key = os.path.normcase(str(root))
        if key in self.roots_seen:
            return
        self.roots_seen.add(key)
        self.signals.extend(dependency_signals(root, check_lockfile=origin == "path"))
        if origin in ("npm-cache", "npm-global"):
            self.signals.extend(installed_tree_signals(root))


def code_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        depth = len(current.relative_to(root).parts)
        if depth and any(d.lower().endswith(".dist-info") for d in dirnames):
            dirnames.clear()
            continue
        dirnames[:] = sorted(
            d
            for d in real_dirs(dirpath, dirnames)
            if d.lower() not in SKIPPED_DIRS and not d.startswith(".")
        )
        if depth >= MAX_DEPTH:
            dirnames.clear()
        for name in sorted(filenames):
            lowered = name.lower()
            if lowered.endswith((".d.ts", ".d.mts", ".d.cts", ".map")):
                continue
            if Path(lowered).suffix in CODE_SUFFIXES:
                yield current / name


def server_base(server: ServerEntry) -> Path:
    base = server.source.path.parent
    if base.name == ".claude-plugin":
        base = base.parent
    return base


def _expand(token: str, server: ServerEntry) -> str:
    base = str(server_base(server))
    for placeholder in (
        "${__dirname}",
        "${CLAUDE_PLUGIN_ROOT}",
        "${extension_dir}",
        "${extensionPath}",
    ):
        token = token.replace(placeholder, base)
    project = server.source.project
    if project is not None:
        for placeholder in WORKSPACE_PLACEHOLDERS:
            token = token.replace(placeholder, str(project))
    return token.strip().strip('"')


def _working_dir(server: ServerEntry) -> Path | None:
    if server.cwd:
        cwd = _expand(server.cwd, server)
        if not cwd or "${" in cwd or is_network_path(cwd):
            return None
        path = Path(cwd)
        if path.is_absolute():
            return path
        base = server.source.project
        return base / path if base is not None else None
    return server.source.project


def _as_path(token: str, server: ServerEntry) -> Path | None:
    if not token or "://" in token or "${" in token or token.startswith("-"):
        return None
    if is_network_path(token):
        return None
    candidate = Path(token)
    if not candidate.is_absolute():
        if server.source.scope in (Scope.EXTENSION, Scope.PLUGIN):
            candidate = server_base(server) / candidate
        else:
            base = _working_dir(server)
            if base is None:
                return None
            candidate = base / candidate
    return candidate


def _exists(path: Path | None) -> bool:
    return path is not None and (_is_file(path) or _is_dir(path))


def _whole(token: str, server: ServerEntry) -> bool:
    if " " not in token:
        return True
    name, eq, value = token.partition("=")
    if eq and name.lower() in DIRECTORY_FLAGS:
        token = value
    return _exists(_as_path(_expand(token, server), server))


def _words(tokens: list[str], server: ServerEntry) -> list[str]:
    words: list[str] = []
    for token in tokens:
        if _whole(token, server):
            words.append(token)
        else:
            words.extend(quoted or plain for quoted, plain in COMMAND_WORD.findall(token))
    return words


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def code_roots(server: ServerEntry) -> list[Path]:
    roots: list[Path] = []
    if server.source.scope in (Scope.EXTENSION, Scope.PLUGIN):
        roots.append(server_base(server))
    words = _words([server.command or "", *server.args], server)
    for index, word in enumerate(words):
        name, eq, value = word.partition("=")
        if eq and name.lower() in DIRECTORY_FLAGS:
            directory = _as_path(_expand(value, server), server)
            if directory is not None and _is_dir(directory):
                roots.append(directory)
            continue
        if word.lower() in DIRECTORY_FLAGS and index + 1 < len(words):
            directory = _as_path(_expand(words[index + 1], server), server)
            if directory is not None and _is_dir(directory):
                roots.append(directory)
            continue
        candidate = _as_path(_expand(word, server), server)
        if (
            candidate is not None
            and candidate.suffix.lower() in CODE_SUFFIXES
            and _is_file(candidate)
        ):
            roots.append(candidate)
            roots.append(candidate.parent)
    working = _working_dir(server) if server.cwd else None
    if working is not None and _is_dir(working):
        roots.append(working)
    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        key = os.path.normcase(str(root))
        if key not in seen:
            seen.add(key)
            unique.append(root)
    return unique


def npm_cache_bases(env: HostEnvironment) -> list[Path]:
    if env.platform == "windows":
        return [env.local_app_data / "npm-cache" / "_npx"]
    return [env.home / ".npm" / "_npx"]


def _package_version(package_dir: Path) -> str | None:
    try:
        document = parse_json(read_text(package_dir / "package.json", 1024 * 1024)).value
    except SafeReadError:
        return None
    version = document.get("version") if isinstance(document, dict) else None
    return version if isinstance(version, str) else None


def _newest(paths: list[Path], marker: str) -> Path:
    def modified(path: Path) -> float:
        try:
            return (path / marker).stat().st_mtime
        except OSError:
            return 0.0

    return max(paths, key=modified)


def find_npm_package(env: HostEnvironment, name: str, version: str | None) -> Path | None:
    candidates: list[Path] = []
    for base in npm_cache_bases(env):
        for cache in child_dirs(base, MAX_CACHE_DIRS):
            package = cache / "node_modules" / Path(*name.split("/"))
            if _is_file(package / "package.json"):
                candidates.append(package)
    if not candidates:
        return None
    if version:
        exact = [c for c in candidates if _package_version(c) == version]
        if exact:
            return _newest(exact, "package.json")
    return _newest(candidates, "package.json")


def uv_site_packages(env: HostEnvironment) -> Iterator[Path]:
    roots = [env.local_app_data / "uv" / "cache" / "archive-v0", env.app_config / "uv" / "tools"]
    if env.platform != "windows":
        roots = [
            env.home / ".cache" / "uv" / "archive-v0",
            env.home / ".local" / "share" / "uv" / "tools",
        ]
    for root in roots:
        for environment in child_dirs(root, MAX_CACHE_DIRS):
            windows_site = environment / "Lib" / "site-packages"
            if _is_dir(windows_site):
                yield windows_site
            for lib in child_dirs(environment / "lib", 10):
                if _is_dir(lib / "site-packages"):
                    yield lib / "site-packages"


def find_pypi_package(env: HostEnvironment, name: str, version: str | None) -> list[Path]:
    normalized = re.sub(r"[-_.]+", "_", name).lower()
    matches: list[tuple[Path, Path]] = []
    for site in uv_site_packages(env):
        for info in child_dirs(site, 500):
            lowered = info.name.lower()
            if not lowered.endswith(".dist-info"):
                continue
            dist_name, _, dist_version = lowered[: -len(".dist-info")].rpartition("-")
            if re.sub(r"[-_.]+", "_", dist_name) != normalized:
                continue
            if version and dist_version != version.lower():
                continue
            matches.append((site, info))
    if not matches:
        return []
    site, info = max(matches, key=lambda item: _mtime(item[1]))
    modules: list[Path] = []
    try:
        top_level = (info / "top_level.txt").read_text(encoding="utf-8").split()
    except OSError:
        top_level = [normalized]
    for module in top_level[:10]:
        if _is_dir(site / module):
            modules.append(site / module)
        elif _is_file(site / f"{module}.py"):
            modules.append(site / f"{module}.py")
    return modules


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _gap(server: ServerEntry) -> ToolGap:
    if server.transport in (Transport.HTTP, Transport.SSE, Transport.WEBSOCKET):
        return ToolGap.REMOTE
    if server.command and program_name(server.command) not in SCRIPT_RUNNERS:
        return ToolGap.BINARY
    return ToolGap.NOT_FOUND


def _shim_files(command: str, env: HostEnvironment) -> list[Path]:
    path = Path(command)
    if path.is_absolute():
        candidates = [path] if path.suffix else [Path(f"{path}{s}") for s in SHIM_SUFFIXES]
    elif "/" in command or "\\" in command or env.platform != "windows":
        return []
    else:
        candidates = [env.app_config / "npm" / f"{command}{s}" for s in SHIM_SUFFIXES]
    return [candidate for candidate in candidates if _is_file(candidate)]


def _npm_global_root(server: ServerEntry, env: HostEnvironment) -> Path | None:
    for shim in _shim_files(server.command or "", env):
        try:
            text = read_text(shim, MAX_SHIM_BYTES)
        except SafeReadError:
            continue
        match = NPM_SHIM_TARGET.search(text)
        if match is None:
            continue
        package = shim.parent / "node_modules" / Path(*re.split(r"[\\/]", match.group(1)))
        if _is_dir(package):
            return package
    return None


def _tool_environments(env: HostEnvironment) -> Iterator[Path]:
    for base in (
        env.app_config / "uv" / "tools",
        env.home / ".local" / "share" / "uv" / "tools",
        env.home / "pipx" / "venvs",
        env.home / ".local" / "pipx" / "venvs",
    ):
        yield from child_dirs(base, MAX_CACHE_DIRS)


def _site_packages(environment: Path) -> Iterator[Path]:
    windows_site = environment / "Lib" / "site-packages"
    if _is_dir(windows_site):
        yield windows_site
    for lib in child_dirs(environment / "lib", 10):
        if _is_dir(lib / "site-packages"):
            yield lib / "site-packages"


def _entry_point_module(site: Path, script: str) -> Path | None:
    for info in child_dirs(site, 500):
        if not info.name.lower().endswith(".dist-info"):
            continue
        try:
            text = read_text(info / "entry_points.txt", MAX_SHIM_BYTES)
        except SafeReadError:
            continue
        for line in text.splitlines():
            name, eq, target = line.partition("=")
            if eq and name.strip().lower() == script.lower():
                return _module_path(site, target.strip().split(":", 1)[0])
    return None


def _module_path(site: Path, module: str) -> Path | None:
    top = module.split(".", 1)[0].strip()
    if not top.isidentifier():
        return None
    if _is_dir(site / top):
        return site / top
    if _is_file(site / f"{top}.py"):
        return site / f"{top}.py"
    return None


def _tool_module(server: ServerEntry, env: HostEnvironment) -> Path | None:
    script = PurePath((server.command or "").replace("\\", "/")).name
    script = script[:-4] if script.lower().endswith(".exe") else script
    if not script or program_name(script) in KNOWN_LAUNCHERS:
        return None
    for environment in _tool_environments(env):
        launchers = (environment / "Scripts" / f"{script}.exe", environment / "bin" / script)
        if not any(_is_file(item) for item in launchers):
            continue
        for site in _site_packages(environment):
            module = _entry_point_module(site, script)
            if module is not None:
                return module
    return None


def _module_argument(args: tuple[str, ...]) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-m":
            return args[index + 1] if index + 1 < len(args) else None
        if not arg.startswith("-"):
            return None
        index += 2 if arg in ("-X", "-W") else 1
    return None


def _python_module(server: ServerEntry, env: HostEnvironment) -> Path | None:
    module = _module_argument(server.args)
    if module is None or any(not part.isidentifier() for part in module.split(".")):
        return None
    working = _working_dir(server)
    if working is not None:
        local = working / Path(*module.split("."))
        for candidate in (local, local.with_suffix(".py")):
            if _exists(candidate):
                return candidate
    for site in _python_sites(server, env):
        found = _module_path(site, module)
        if found is not None:
            return found
    return None


def _python_sites(server: ServerEntry, env: HostEnvironment) -> Iterator[Path]:
    command = Path(server.command or "")
    if command.is_absolute() and command.parent.name.lower() in ("scripts", "bin"):
        yield from _site_packages(command.parent.parent)
    for version in child_dirs(env.app_config / "Python", 50):
        if _is_dir(version / "site-packages"):
            yield version / "site-packages"
    for version in child_dirs(env.local_app_data / "Programs" / "Python", 50):
        yield from _site_packages(version)
    yield from uv_site_packages(env)


def installed_roots(server: ServerEntry, env: HostEnvironment) -> list[tuple[Path, str]]:
    if not server.command or server.transport is not Transport.STDIO:
        return []
    if program_name(server.command) in PYTHON_PROGRAMS:
        module = _python_module(server, env)
        return [(module, "python-module")] if module is not None else []
    if program_name(server.command) in KNOWN_LAUNCHERS:
        return []
    package = _npm_global_root(server, env)
    if package is not None:
        return [(package, "npm-global")]
    module = _tool_module(server, env)
    return [(module, "uv-tool")] if module is not None else []


def skill_scripts(root: Path) -> Iterator[Path]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(
            d for d in real_dirs(dirpath, dirnames) if d.lower() not in SKIPPED_DIRS
        )
        if len(current.relative_to(root).parts) >= SKILL_SCRIPT_DEPTH:
            dirnames.clear()
        for name in sorted(filenames):
            if Path(name.lower()).suffix in SCRIPT_SUFFIXES:
                count += 1
                if count > MAX_SKILL_SCRIPTS:
                    return
                yield current / name


def collect_skill(server: ServerEntry) -> ToolCollection:
    collector = _Collector()
    path = server.source.path
    try:
        text = read_text(path, MAX_SKILL_BYTES)
    except SafeReadError as exc:
        return ToolCollection(
            gap=ToolGap.NOT_FOUND, notes=(f"unreadable:{path} ({exc.code.value})",)
        )
    document = parse_skill(text)
    collector.tools.append(skill_definition(path, server.name, document))
    collector.signals.extend(skill_signals(path, document))
    collector.origins.append(f"skill:{path}")
    for script in skill_scripts(path.parent):
        collector.signals.append(
            CodeSignal(
                SignalKind.SKILL_SCRIPT, Location(script), script.name, script.suffix.lower()
            )
        )
        if script.suffix.lower() in CODE_SUFFIXES:
            collector.scan_file(script)
            continue
        try:
            script_text = read_text(script, MAX_FILE_BYTES)
        except SafeReadError as exc:
            collector.note("unreadable", f"{script} ({exc.code.value})")
            continue
        collector.files += 1
        collector.signals.extend(shell_script_signals(script, script_text))
    return ToolCollection(
        tools=tuple(collector.tools),
        origins=tuple(collector.origins),
        files_scanned=collector.files,
        notes=tuple(collector.notes),
        signals=tuple(collector.signals),
    )


def collect_tools(server: ServerEntry, env: HostEnvironment) -> ToolCollection:
    if server.source.scope is Scope.SKILL:
        return collect_skill(server)
    collector = _Collector()
    if server.source.scope is Scope.EXTENSION:
        collector.scan_manifest(server.source.path, "manifest")
    if server.source.scope is Scope.PATH:
        collector.scan_root(server.source.path, "path")
    for root in code_roots(server):
        collector.scan_root(root, "source")
    effective = effective_command(server)
    runner = parse_runner(effective.command, effective.args)
    if runner is not None:
        for package in runner.packages:
            if package.remote:
                continue
            exact = package.version if package.pinned else None
            if package.ecosystem == "npm":
                directory = find_npm_package(env, package.name, exact)
                if directory is not None:
                    collector.scan_root(directory, "npm-cache")
            else:
                for module in find_pypi_package(env, package.name, exact):
                    collector.scan_root(module, "uv-cache")
    if not collector.origins:
        for root, origin in installed_roots(server, env):
            collector.scan_root(root, origin)
    gap = None if collector.origins else _gap(server)
    if server.source.scope is Scope.PATH and not collector.origins:
        gap = ToolGap.NO_SOURCE
    return ToolCollection(
        tools=dedupe(collector.tools),
        origins=tuple(collector.origins),
        gap=gap,
        files_scanned=collector.files,
        notes=tuple(collector.notes),
        signals=tuple(collector.signals),
    )
