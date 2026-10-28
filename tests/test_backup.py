from __future__ import annotations

from pathlib import Path

import pytest

from guardia.backup import (
    BACKUP_SUFFIX,
    BackupError,
    create,
    extract,
    listing,
)
from guardia.secure_store import RAW_PROTECTOR


def seed(data_dir: Path) -> dict[str, bytes]:
    data_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "registro.jsonl": b'{"seq": 1}\n',
        "registro.key": b"GRAW1\nsecret-key-bytes",
        "regole.approvate.toml": b"[rule]\nid = 'x'\n",
    }
    for name, content in files.items():
        (data_dir / name).write_bytes(content)
    (data_dir / "registro.lock").write_bytes(b"")
    return files


def test_backup_round_trip(tmp_path: Path) -> None:
    data = tmp_path / "data"
    files = seed(data)
    archive = create(data, protector=RAW_PROTECTOR)
    assert archive.suffix == BACKUP_SUFFIX
    restored = extract(archive, tmp_path / "out", protector=RAW_PROTECTOR)
    names = {path.name for path in restored}
    assert names == set(files)
    for name, content in files.items():
        assert (tmp_path / "out" / name).read_bytes() == content


def test_lock_files_are_not_backed_up(tmp_path: Path) -> None:
    data = tmp_path / "data"
    seed(data)
    archive = create(data, protector=RAW_PROTECTOR)
    restored = extract(archive, tmp_path / "out", protector=RAW_PROTECTOR)
    assert all(path.suffix != ".lock" for path in restored)


def test_rotation_keeps_only_the_newest(tmp_path: Path) -> None:
    data = tmp_path / "data"
    seed(data)
    for _ in range(5):
        create(data, keep=3, protector=RAW_PROTECTOR)
    assert len(listing(data)) == 3


def test_backups_folder_is_not_inside_a_backup(tmp_path: Path) -> None:
    data = tmp_path / "data"
    seed(data)
    create(data, protector=RAW_PROTECTOR)
    archive = create(data, protector=RAW_PROTECTOR)
    restored = extract(archive, tmp_path / "out", protector=RAW_PROTECTOR)
    assert all("backups" not in path.parts for path in restored)


def test_unknown_format_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.gbk"
    bad.write_bytes(b"not a guardia backup")
    with pytest.raises(BackupError):
        extract(bad, tmp_path / "out", protector=RAW_PROTECTOR)


def test_listing_is_empty_without_backups(tmp_path: Path) -> None:
    assert listing(tmp_path / "data") == []
