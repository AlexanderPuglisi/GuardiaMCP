from __future__ import annotations

import contextlib
import io
import os
import secrets
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from guardia.secure_store import KeyStoreError, Protector, default_protector

BACKUP_DIR = "backups"
BACKUP_SUFFIX = ".gbk"
BACKUP_GLOB = "guardia-backup-*" + BACKUP_SUFFIX
DEFAULT_KEEP = 10
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


class BackupError(Exception):
    pass


def _members(data_dir: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(data_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(data_dir)
        if relative.parts and relative.parts[0] == BACKUP_DIR:
            continue
        if path.suffix == ".lock" or path.name.startswith("."):
            continue
        found.append(path)
    return found


def _archive(data_dir: Path, files: list[Path]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in files:
            tar.add(str(path), arcname=path.relative_to(data_dir).as_posix())
    return buffer.getvalue()


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def listing(data_dir: Path) -> list[Path]:
    try:
        return sorted((data_dir / BACKUP_DIR).glob(BACKUP_GLOB))
    except OSError:
        return []


def _rotate(folder: Path, keep: int) -> list[Path]:
    backups = sorted(folder.glob(BACKUP_GLOB))
    removed: list[Path] = []
    for path in backups[: max(len(backups) - keep, 0)]:
        with contextlib.suppress(OSError):
            path.unlink()
            removed.append(path)
    return removed


def create(data_dir: Path, keep: int = DEFAULT_KEEP, protector: Protector | None = None) -> Path:
    protector = protector or default_protector()
    payload = protector.magic + protector.protect(_archive(data_dir, _members(data_dir)))
    folder = data_dir / BACKUP_DIR
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"guardia-backup-{_stamp()}-{secrets.token_hex(2)}{BACKUP_SUFFIX}"
    handle, temporary = tempfile.mkstemp(prefix=".backup-", dir=folder)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(temporary).unlink()
        raise
    _rotate(folder, keep)
    return target


def extract(archive: Path, destination: Path, protector: Protector | None = None) -> list[Path]:
    protector = protector or default_protector()
    try:
        payload = archive.read_bytes()
    except OSError as exc:
        raise BackupError(exc.strerror or type(exc).__name__) from exc
    if not payload.startswith(protector.magic):
        raise BackupError("unknown backup format")
    try:
        raw = protector.unprotect(payload[len(protector.magic) :])
    except (KeyStoreError, OSError, ValueError) as exc:
        raise BackupError(str(exc)) from exc
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise BackupError("archive too large")
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            tar.extractall(path=destination, filter="data")
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise BackupError(str(exc)) from exc
    return sorted(path for path in destination.rglob("*") if path.is_file())
