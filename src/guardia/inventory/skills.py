from __future__ import annotations

import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guardia.inventory.environment import HostEnvironment
from guardia.inventory.locations import PRUNED_DIRS, child_dirs
from guardia.model import (
    Client,
    ConfigSource,
    Scope,
    ServerEntry,
    Transport,
    frozen_mapping,
    sha256_hex,
)
from guardia.safeio import SafeReadError, read_text

SKILL_FILE = "SKILL.md"
MAX_SKILL_BYTES = 2 * 1024 * 1024
MAX_SKILLS = 2000
SKILL_WALK_DEPTH = 7
FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(?P<body>.*?)\r?\n---[ \t]*(\r?\n|\Z)", re.DOTALL)
KEY_LINE = re.compile(r"^(?P<key>[A-Za-z0-9_.-]+)\s*:\s*(?P<value>.*)$")


@dataclass(frozen=True, slots=True)
class SkillDocument:
    frontmatter: Mapping[str, Any]
    body: str
    body_line: int
    text: str


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_frontmatter(block: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    lines = block.splitlines()
    index = 0
    while index < len(lines):
        match = KEY_LINE.match(lines[index])
        index += 1
        if match is None:
            continue
        key, value = match["key"], match["value"].strip()
        continuation: list[str] = []
        while index < len(lines) and (
            lines[index].startswith((" ", "\t")) or not lines[index].strip()
        ):
            continuation.append(lines[index].strip())
            index += 1
        items = [line[1:].strip() for line in continuation if line.startswith("-")]
        if not value and items:
            result[key] = [_unquote(item) for item in items]
        elif value in ("|", ">", "|-", ">-", "|+", ">+"):
            joiner = "\n" if value.startswith("|") else " "
            result[key] = joiner.join(line for line in continuation if line).strip()
        else:
            parts = [_unquote(value), *(line for line in continuation if line)]
            result[key] = " ".join(part for part in parts if part)
    return result


def parse_skill(text: str) -> SkillDocument:
    match = FRONTMATTER.match(text)
    if match is None:
        return SkillDocument(frozen_mapping(), text, 1, text)
    frontmatter = parse_frontmatter(match["body"])
    body_line = text.count("\n", 0, match.end()) + 1
    return SkillDocument(frozen_mapping(frontmatter), text[match.end() :], body_line, text)


def skill_entry(path: Path, client: Client) -> ServerEntry | None:
    try:
        text = read_text(path, MAX_SKILL_BYTES)
    except SafeReadError:
        return None
    document = parse_skill(text)
    declared = document.frontmatter.get("name")
    name = declared if isinstance(declared, str) and declared.strip() else path.parent.name
    raw = {**document.frontmatter, "body_sha256": sha256_hex(document.body.encode("utf-8"))}
    return ServerEntry(
        name=name,
        source=ConfigSource(client, Scope.SKILL, path),
        pointer="",
        transport=Transport.UNKNOWN,
        raw=frozen_mapping(raw),
    )


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _direct_skills(base: Path) -> Iterator[Path]:
    try:
        entries = sorted(base.iterdir())
    except OSError:
        return
    for entry in entries[:MAX_SKILLS]:
        candidate = entry / SKILL_FILE
        if _is_file(candidate):
            yield candidate


def _walk_skills(base: Path, depth: int = SKILL_WALK_DEPTH) -> Iterator[Path]:
    try:
        if not base.is_dir():
            return
    except OSError:
        return
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNED_DIRS and d != "marketplaces")
        if len(current.relative_to(base).parts) >= depth:
            dirnames.clear()
        if SKILL_FILE in filenames:
            yield current / SKILL_FILE


def skill_locations(env: HostEnvironment, projects: list[Path]) -> Iterator[tuple[Path, Client]]:
    claude = env.home / ".claude"
    for path in _direct_skills(claude / "skills"):
        yield path, Client.CLAUDE_CODE
    for base in (
        claude / "skills" / "synced",
        claude / "plugins" / "synced",
        claude / "plugins" / "cache",
    ):
        for path in _walk_skills(base):
            yield path, Client.CLAUDE_CODE
    for profile in child_dirs(env.local_app_data / "Claude-Data"):
        if not profile.name.startswith("claude_"):
            continue
        for sub in ("local-agent-mode-sessions", "rpm"):
            for path in _walk_skills(profile / sub):
                yield path, Client.CLAUDE_DESKTOP
    for project in projects:
        for path in _direct_skills(project / ".claude" / "skills"):
            yield path, Client.CLAUDE_CODE


def discover_skills(env: HostEnvironment, projects: list[Path]) -> tuple[ServerEntry, ...]:
    entries: list[ServerEntry] = []
    seen: set[str] = set()
    for path, client in skill_locations(env, projects):
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        entry = skill_entry(path, client)
        if entry is not None:
            entries.append(entry)
        if len(entries) >= MAX_SKILLS:
            break
    return tuple(entries)
