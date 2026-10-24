from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import IO

from guardia.shield.windows import KILLED_EXIT_CODE, Job

GRACE_SECONDS = 5.0
KILL_WAIT_SECONDS = 10.0
POLL_SECONDS = 0.2
CONFIRM_OUTPUT_LIMIT = 64 * 1024
BATCH_SUFFIXES = (".cmd", ".bat")
CMD_SPECIAL = re.compile(r'[\s"&|<>^()%!,;=]')


class LaunchError(Exception):
    pass


class UnsafeArgumentError(LaunchError):
    pass


def resolve(command: Sequence[str]) -> list[str]:
    if not command or not command[0] or "\x00" in "".join(command):
        raise LaunchError("empty command")
    program = command[0]
    found = shutil.which(program)
    if found is None and Path(program).is_file():
        found = program
    if found is None:
        raise LaunchError(program)
    return [found, *command[1:]]


def cmd_quote(argument: str) -> str:
    if argument and not CMD_SPECIAL.search(argument):
        return argument
    parts: list[str] = []
    slashes = 0
    for char in argument:
        if char == "\\":
            slashes += 1
            continue
        if char == '"':
            parts.append("\\" * (slashes * 2) + '""')
        else:
            parts.append("\\" * slashes + char)
        slashes = 0
    parts.append("\\" * (slashes * 2))
    return '"' + "".join(parts) + '"'


def command_line(
    argv: Sequence[str], *, windows: bool = sys.platform == "win32"
) -> str | list[str]:
    if not windows or not argv[0].lower().endswith(BATCH_SUFFIXES):
        return list(argv)
    if any("\n" in part or "\r" in part for part in argv):
        raise UnsafeArgumentError(argv[0])
    return " ".join(cmd_quote(part) for part in argv)


class ServerProcess:
    def __init__(self, process: subprocess.Popen[bytes], job: Job | None = None) -> None:
        self._process = process
        self._job = job or Job(None)

    @classmethod
    def start(cls, command: Sequence[str]) -> ServerProcess:
        argv = resolve(command)
        line = command_line(argv)
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            process = subprocess.Popen(
                line,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                shell=False,
                creationflags=flags,
            )
        except OSError as exc:
            raise LaunchError(str(exc)) from exc
        return cls(process, Job.around(process.pid))

    @property
    def stdin(self) -> IO[bytes]:
        stream = self._process.stdin
        if stream is None:
            raise LaunchError("no stdin")
        return stream

    @property
    def stdout(self) -> IO[bytes]:
        stream = self._process.stdout
        if stream is None:
            raise LaunchError("no stdout")
        return stream

    @property
    def pid(self) -> int:
        return self._process.pid

    def close_input(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            self.stdin.close()

    def wait(self, timeout: float) -> int | None:
        try:
            return self._process.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    @property
    def contained(self) -> bool:
        return self._job.active

    def kill(self) -> None:
        if self._job.terminate():
            return
        with contextlib.suppress(OSError):
            self._process.kill()

    def stop(self, grace: float = GRACE_SECONDS) -> int:
        self.close_input()
        code = self.wait(grace)
        if code is None:
            self.kill()
            code = self.wait(KILL_WAIT_SECONDS)
        self._job.close()
        return KILLED_EXIT_CODE if code is None else code


def _exchange(
    process: subprocess.Popen[bytes],
    payload: bytes,
    timeout: float,
    cancelled: threading.Event | None,
) -> bytes | None:
    deadline = time.monotonic() + timeout
    data: bytes | None = payload
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or (cancelled is not None and cancelled.is_set()):
            return None
        try:
            output, _ = process.communicate(data, timeout=min(remaining, POLL_SECONDS))
        except subprocess.TimeoutExpired:
            data = None
            continue
        return output


def run_confirmation(
    command: Sequence[str],
    payload: bytes,
    timeout: float,
    cancelled: threading.Event | None = None,
) -> bytes | None:
    try:
        argv = resolve(command)
    except LaunchError:
        return None
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=flags,
        )
    except OSError:
        return None
    job = Job.around(process.pid)
    try:
        output = _exchange(process, payload, timeout, cancelled)
        if output is None:
            if not job.terminate():
                with contextlib.suppress(OSError):
                    process.kill()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError, ValueError):
                process.communicate(timeout=KILL_WAIT_SECONDS)
            return None
    finally:
        job.close()
    if process.returncode != 0:
        return None
    return output[:CONFIRM_OUTPUT_LIMIT]
