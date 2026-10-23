from __future__ import annotations

import contextlib
import os
import secrets
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

KEY_BYTES = 32
DPAPI_MAGIC = b"GDPAPI1\n"
RAW_MAGIC = b"GRAW1\n"
DPAPI_DESCRIPTION = "Guardia MCP ledger key"
CRYPTPROTECT_UI_FORBIDDEN = 0x01

Transform = Callable[[bytes], bytes]


class KeyStoreError(Exception):
    pass


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _call(protect: bool, data: bytes) -> bytes:
        buffer = ctypes.create_string_buffer(data, len(data))
        source = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
        target = _Blob()
        crypt32 = ctypes.windll.crypt32
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(source),
                DPAPI_DESCRIPTION,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(target),
            )
        else:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(source),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(target),
            )
        if not ok:
            raise KeyStoreError(f"DPAPI error {ctypes.GetLastError()}")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(target.pbData)

    def dpapi_protect(data: bytes) -> bytes:
        return _call(True, data)

    def dpapi_unprotect(data: bytes) -> bytes:
        return _call(False, data)


@dataclass(frozen=True, slots=True)
class Protector:
    magic: bytes
    protect: Transform
    unprotect: Transform


def _identity(data: bytes) -> bytes:
    return data


RAW_PROTECTOR = Protector(RAW_MAGIC, _identity, _identity)


def default_protector() -> Protector:
    if sys.platform == "win32":
        return Protector(DPAPI_MAGIC, dpapi_protect, dpapi_unprotect)
    return RAW_PROTECTOR


class KeyStore:
    def __init__(self, path: Path, protector: Protector | None = None) -> None:
        self.path = path
        self.protector = protector or default_protector()

    def load(self) -> bytes | None:
        try:
            payload = self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise KeyStoreError(exc.strerror or type(exc).__name__) from exc
        if not payload.startswith(self.protector.magic):
            raise KeyStoreError("unknown key format")
        try:
            key = self.protector.unprotect(payload[len(self.protector.magic) :])
        except (KeyStoreError, OSError, ValueError) as exc:
            raise KeyStoreError(str(exc)) from exc
        if len(key) != KEY_BYTES:
            raise KeyStoreError("invalid key length")
        return key

    def create(self) -> bytes:
        key = secrets.token_bytes(KEY_BYTES)
        payload = self.protector.magic + self.protector.protect(key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=".key-", dir=self.path.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
            if sys.platform != "win32":
                Path(temporary).chmod(0o600)
            Path(temporary).replace(self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                Path(temporary).unlink()
            raise
        return key

    def load_or_create(self) -> tuple[bytes, bool]:
        key = self.load()
        if key is not None:
            return key, False
        return self.create(), True
