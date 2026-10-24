from __future__ import annotations

import enum
import os
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath

SHIELD_WORDS = frozenset({"scudo", "shield"})
NAME_OPTIONS = frozenset({"--server", "--nome"})
GUARDIA_PROGRAMS = frozenset({"guardia", "guardia.exe"})
COMMAND_LINE_PROGRAM = "guardia.exe"
PYTHON_FLAGS = frozenset({"-I", "-E", "-s", "-P", "-B", "-u"})


class LauncherState(enum.StrEnum):
    CURRENT = "current"
    OTHER = "other"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class Wrapped:
    command: str
    args: tuple[str, ...]
    name: str
    launcher: tuple[str, ...] = ()


def _program(command: str) -> str:
    return PurePath(command.replace("\\", "/")).name.lower()


def unwrap(command: str | None, args: Sequence[str]) -> Wrapped | None:
    if not command:
        return None
    program = _program(command)
    rest = list(args)
    if program.startswith("python") or program in {"py", "py.exe", "pythonw.exe"}:
        flags = 0
        while flags < len(rest) and rest[flags] in PYTHON_FLAGS:
            flags += 1
        if rest[flags : flags + 2] != ["-m", "guardia"]:
            return None
        starter: tuple[str, ...] = (command, *rest[: flags + 2])
        rest = rest[flags + 2 :]
    elif program in GUARDIA_PROGRAMS:
        starter = (command,)
    else:
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
    return Wrapped(original[0], tuple(original[1:]), name, starter)


def launcher() -> list[str]:
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).with_name(COMMAND_LINE_PROGRAM))]
    return [sys.executable, "-I", "-m", "guardia"]


def _same_program(first: str, second: str) -> bool:
    return os.path.normcase(str(Path(first).absolute())) == os.path.normcase(
        str(Path(second).absolute())
    )


def launcher_state(used: Sequence[str], current: Sequence[str] | None = None) -> LauncherState:
    wanted = list(launcher() if current is None else current)
    if not used:
        return LauncherState.MISSING
    if (
        len(used) == len(wanted)
        and _same_program(used[0], wanted[0])
        and list(used[1:]) == wanted[1:]
    ):
        return LauncherState.CURRENT
    program = Path(used[0])
    found = program.is_file() if program.is_absolute() else shutil.which(used[0]) is not None
    return LauncherState.OTHER if found else LauncherState.MISSING


def wrap(
    starter: Sequence[str], name: str, command: str, args: Sequence[str]
) -> tuple[str, list[str]]:
    return starter[0], [*starter[1:], "scudo", "--server", name, "--", command, *args]
