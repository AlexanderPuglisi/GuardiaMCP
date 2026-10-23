from __future__ import annotations

import functools
import re
import tomllib
from collections.abc import Iterator, Mapping
from importlib import resources
from pathlib import Path
from typing import Any

from guardia.inventory.locations import child_dirs
from guardia.locate import json_lines
from guardia.model import CodeSignal, Location, SignalKind, json_pointer
from guardia.safeio import SafeReadError, parse_json, parse_toml, read_text
from guardia.scanner.checks import DOWNLOAD_EXECUTE, known_packages
from guardia.scanner.commandline import GITHUB_SHORTHAND, REMOTE_SPEC, damerau_levenshtein

INSTALL_HOOKS = ("preinstall", "install", "postinstall")
DEPENDENCY_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
        "uv.lock",
        "poetry.lock",
        "pipfile.lock",
        "pdm.lock",
    }
)
DANGEROUS_SCRIPT = re.compile(
    r"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|certutil|bitsadmin)\b"
    r"|https?://|powershell(\.exe)?\s+[^|&;]*-(e|enc|encodedcommand)\b|base64",
    re.IGNORECASE,
)
REQUIREMENT_NAME = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[=<>!~@].*)?$"
)
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_INSTALLED_PACKAGES = 3000


@functools.cache
def popular_packages() -> dict[str, frozenset[str]]:
    path = resources.files("guardia.scanner").joinpath("data", "popular_packages.toml")
    data = tomllib.loads(path.read_text("utf-8"))
    known = known_packages()
    return {
        ecosystem: frozenset(_normalize(ecosystem, n) for n in [*names, *known.get(ecosystem, ())])
        for ecosystem, names in data.items()
    }


def _normalize(ecosystem: str, name: str) -> str:
    lowered = name.strip().lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem == "pypi" else lowered


def lookalike(ecosystem: str, name: str) -> str | None:
    normalized = _normalize(ecosystem, name)
    popular = popular_packages().get(ecosystem, frozenset())
    if len(normalized) < 5 or normalized in popular:
        return None
    for candidate in sorted(popular):
        if len(candidate) >= 5 and damerau_levenshtein(normalized, candidate, 1) == 1:
            return candidate
    return None


def _locator(path: Path, text: str) -> Any:
    lines = json_lines(text)

    def locate(pointer: str) -> Location:
        return Location(path, pointer, lines.get(pointer) or lines.get(pointer.rsplit("/", 1)[0]))

    return locate


def _signal(kind: SignalKind, location: Location, evidence: str, detail: str = "") -> CodeSignal:
    return CodeSignal(kind, location, evidence[:160], detail)


def _npm_spec_remote(spec: str) -> bool:
    lowered = spec.strip().lower()
    if lowered.startswith(("file:", "link:", "workspace:", "npm:", "portal:")):
        return False
    return bool(REMOTE_SPEC.match(spec)) or bool(GITHUB_SHORTHAND.match(spec.strip()))


def package_json_signals(path: Path, *, include_dependencies: bool = True) -> Iterator[CodeSignal]:
    try:
        parsed = parse_json(read_text(path, MAX_MANIFEST_BYTES))
    except SafeReadError:
        return
    document = parsed.value
    if not isinstance(document, Mapping):
        return
    locate = _locator(path, parsed.text)
    name = str(document.get("name", path.parent.name))
    scripts = document.get("scripts")
    if isinstance(scripts, Mapping):
        for hook in INSTALL_HOOKS:
            script = scripts.get(hook)
            if isinstance(script, str) and script.strip():
                danger = (
                    "dangerous"
                    if DANGEROUS_SCRIPT.search(script) or DOWNLOAD_EXECUTE.search(script)
                    else ""
                )
                yield _signal(
                    SignalKind.INSTALL_SCRIPT,
                    locate(json_pointer("scripts", hook)),
                    f"{name} {hook}: {script}",
                    danger,
                )
    if not include_dependencies:
        return
    for section in DEPENDENCY_SECTIONS:
        dependencies = document.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        for dependency, spec in dependencies.items():
            location = locate(json_pointer(section, str(dependency)))
            text = spec if isinstance(spec, str) else ""
            if _npm_spec_remote(text):
                yield _signal(SignalKind.DEPENDENCY_REMOTE, location, f"{dependency}: {text}")
            elif text.strip().lower() in ("", "*", "latest", "x"):
                yield _signal(
                    SignalKind.DEPENDENCY_UNPINNED, location, f"{dependency}: {text or '-'}"
                )
            similar = lookalike("npm", str(dependency))
            if similar:
                yield _signal(SignalKind.DEPENDENCY_LOOKALIKE, location, str(dependency), similar)


def _python_requirement(
    requirement: str, location: Location, *, report_unpinned: bool
) -> Iterator[CodeSignal]:
    text = requirement.split("#", 1)[0].strip().split(";", 1)[0].strip()
    if not text or text.startswith("-"):
        return
    if REMOTE_SPEC.match(text) or " @ " in text or "@git+" in text.replace(" ", ""):
        yield _signal(SignalKind.DEPENDENCY_REMOTE, location, text)
        return
    match = REQUIREMENT_NAME.match(text)
    if match is None:
        return
    name = match["name"]
    if report_unpinned and not match["spec"]:
        yield _signal(SignalKind.DEPENDENCY_UNPINNED, location, text)
    similar = lookalike("pypi", name)
    if similar:
        yield _signal(SignalKind.DEPENDENCY_LOOKALIKE, location, name, similar)


def requirements_signals(path: Path, *, report_unpinned: bool) -> Iterator[CodeSignal]:
    try:
        text = read_text(path, MAX_MANIFEST_BYTES)
    except SafeReadError:
        return
    for number, line in enumerate(text.splitlines(), start=1):
        yield from _python_requirement(
            line, Location(path, "", number), report_unpinned=report_unpinned
        )


def pyproject_signals(path: Path) -> Iterator[CodeSignal]:
    try:
        document = parse_toml(read_text(path, MAX_MANIFEST_BYTES)).value
    except SafeReadError:
        return
    project = document.get("project")
    requirements: list[str] = []
    if isinstance(project, Mapping):
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            requirements.extend(d for d in dependencies if isinstance(d, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, Mapping):
            for group in optional.values():
                if isinstance(group, list):
                    requirements.extend(d for d in group if isinstance(d, str))
    for requirement in requirements:
        yield from _python_requirement(requirement, Location(path), report_unpinned=False)
    poetry = (
        document.get("tool", {}).get("poetry", {})
        if isinstance(document.get("tool"), Mapping)
        else {}
    )
    poetry_dependencies = poetry.get("dependencies") if isinstance(poetry, Mapping) else None
    if isinstance(poetry_dependencies, Mapping):
        for name, spec in poetry_dependencies.items():
            if isinstance(spec, Mapping) and ("git" in spec or "url" in spec):
                yield _signal(SignalKind.DEPENDENCY_REMOTE, Location(path), f"{name}: {dict(spec)}")
            similar = lookalike("pypi", str(name))
            if similar and name != "python":
                yield _signal(SignalKind.DEPENDENCY_LOOKALIKE, Location(path), str(name), similar)


def _has_lockfile(root: Path) -> bool:
    try:
        return any(entry.name.lower() in LOCKFILES for entry in root.iterdir())
    except OSError:
        return False


def dependency_signals(root: Path, *, check_lockfile: bool) -> list[CodeSignal]:
    signals: list[CodeSignal] = []
    locked = _has_lockfile(root)
    manifests = 0
    package = root / "package.json"
    if package.is_file():
        manifests += 1
        signals.extend(package_json_signals(package))
    try:
        requirement_files = sorted(root.glob("requirements*.txt"))
    except OSError:
        requirement_files = []
    for requirements in requirement_files:
        manifests += 1
        signals.extend(requirements_signals(requirements, report_unpinned=not locked))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        manifests += 1
        signals.extend(pyproject_signals(pyproject))
    if check_lockfile and manifests and not locked:
        signals.append(_signal(SignalKind.NO_LOCKFILE, Location(root), str(root)))
    return signals


def _installed_packages(node_modules: Path) -> Iterator[Path]:
    count = 0
    for entry in child_dirs(node_modules, MAX_INSTALLED_PACKAGES):
        if entry.name.startswith("."):
            continue
        children = child_dirs(entry, 500) if entry.name.startswith("@") else [entry]
        for package in children:
            count += 1
            if count > MAX_INSTALLED_PACKAGES:
                return
            yield package


def installed_tree_signals(package_dir: Path) -> list[CodeSignal]:
    node_modules = next((p for p in package_dir.parents if p.name == "node_modules"), None)
    if node_modules is None:
        return []
    signals: list[CodeSignal] = []
    for package in _installed_packages(node_modules):
        if package == package_dir:
            continue
        manifest = package / "package.json"
        if manifest.is_file():
            signals.extend(package_json_signals(manifest, include_dependencies=False))
        similar = lookalike(
            "npm",
            package.name
            if not package.parent.name.startswith("@")
            else f"{package.parent.name}/{package.name}",
        )
        if similar:
            signals.append(
                _signal(SignalKind.DEPENDENCY_LOOKALIKE, Location(manifest), package.name, similar)
            )
    return signals
