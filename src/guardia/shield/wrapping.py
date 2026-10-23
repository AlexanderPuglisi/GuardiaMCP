from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePath

SHIELD_WORDS = frozenset({"scudo", "shield"})
NAME_OPTIONS = frozenset({"--server", "--nome"})
GUARDIA_PROGRAMS = frozenset({"guardia", "guardia.exe"})


@dataclass(frozen=True, slots=True)
class Wrapped:
    command: str
    args: tuple[str, ...]
    name: str


def _program(command: str) -> str:
    return PurePath(command.replace("\\", "/")).name.lower()


def unwrap(command: str | None, args: Sequence[str]) -> Wrapped | None:
    if not command:
        return None
    program = _program(command)
    rest = list(args)
    if program.startswith("python") or program in {"py", "py.exe", "pythonw.exe"}:
        if rest[:2] != ["-m", "guardia"]:
            return None
        rest = rest[2:]
    elif program not in GUARDIA_PROGRAMS:
        return None
    if not rest or rest[0] not in SHIELD_WORDS or "--" not in rest:
        return None
    split = rest.index("--")
    options = rest[1:split]
    original = rest[split + 1 :]
    if not original:
        return None
    name = ""
    for index, option in enumerate(options[:-1]):
        if option in NAME_OPTIONS:
            name = options[index + 1]
    return Wrapped(original[0], tuple(original[1:]), name)


def launcher() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "guardia"]


def wrap(
    starter: Sequence[str], name: str, command: str, args: Sequence[str]
) -> tuple[str, list[str]]:
    return starter[0], [*starter[1:], "scudo", "--server", name, "--", command, *args]
