from __future__ import annotations

import contextlib
import enum
import threading
from dataclasses import dataclass
from typing import IO

MAX_MESSAGE_BYTES = 32 * 1024 * 1024
DISCARD_CHUNK = 1024 * 1024


class FrameStatus(enum.Enum):
    MESSAGE = "message"
    OVERSIZED = "oversized"
    END = "end"


@dataclass(frozen=True, slots=True)
class Frame:
    status: FrameStatus
    data: bytes = b""
    size: int = 0


def _discard_line(stream: IO[bytes]) -> int:
    discarded = 0
    while True:
        chunk = stream.readline(DISCARD_CHUNK)
        discarded += len(chunk)
        if not chunk or chunk.endswith(b"\n"):
            return discarded


def read_frame(stream: IO[bytes], limit: int = MAX_MESSAGE_BYTES) -> Frame:
    while True:
        try:
            line = stream.readline(limit + 1)
        except (OSError, ValueError):
            return Frame(FrameStatus.END)
        if not line:
            return Frame(FrameStatus.END)
        if len(line) > limit and not line.endswith(b"\n"):
            return Frame(FrameStatus.OVERSIZED, size=len(line) + _discard_line(stream))
        data = line.rstrip(b"\r\n")
        if data.strip():
            return Frame(FrameStatus.MESSAGE, data, len(data))


class FrameWriter:
    def __init__(self, stream: IO[bytes]) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self.closed = False

    def write(self, data: bytes) -> bool:
        with self._lock:
            if self.closed:
                return False
            try:
                self._stream.write(data + b"\n")
                self._stream.flush()
            except (OSError, ValueError):
                self.closed = True
                return False
            return True

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
            with contextlib.suppress(OSError, ValueError):
                self._stream.close()
