from __future__ import annotations

import contextlib
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO

GRACE_SECONDS = 5.0
CONFIRM_OUTPUT_LIMIT = 64 * 1024


class LaunchError(Exception):
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


class ServerProcess:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    @classmethod
    def start(cls, command: Sequence[str]) -> ServerProcess:
        argv = resolve(command)
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,
                shell=False,
                creationflags=flags,
            )
        except OSError as exc:
            raise LaunchError(str(exc)) from exc
        return cls(process)

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

    def stop(self, grace: float = GRACE_SECONDS) -> int:
        self.close_input()
        code = self.wait(grace)
        if code is not None:
            return code
        with contextlib.suppress(OSError):
            self._process.kill()
        return self._process.wait()


def run_confirmation(command: Sequence[str], payload: bytes, timeout: float) -> bytes | None:
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
    try:
        output, _ = process.communicate(payload, timeout=timeout)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            process.kill()
        process.communicate()
        return None
    if process.returncode != 0:
        return None
    return output[:CONFIRM_OUTPUT_LIMIT]
