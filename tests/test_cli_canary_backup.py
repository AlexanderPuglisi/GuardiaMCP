from __future__ import annotations

import io
import re
from pathlib import Path

from guardia import backup
from guardia.canary import CANARY_PREFIX
from guardia.cli import main
from guardia.inventory import HostEnvironment


def run_cli(env: HostEnvironment, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(argv), env=env, stdout=out)
    return code, out.getvalue()


def test_canary_create_prints_the_token(env: HostEnvironment) -> None:
    code, out = run_cli(env, "canary", "create", "--lang", "en")
    assert code == 0
    assert CANARY_PREFIX in out


def test_canary_lifecycle(env: HostEnvironment) -> None:
    code, created = run_cli(env, "esca", "crea", "--nota", "esca scrivania")
    assert code == 0
    match = re.search(r"\b([0-9a-f]{8})\b", created)
    assert match is not None
    identifier = match.group(1)
    code, listed = run_cli(env, "esca", "elenco")
    assert code == 0
    assert "esca scrivania" in listed
    assert identifier in listed
    code, _ = run_cli(env, "esca", "rimuovi", identifier)
    assert code == 0
    code, again = run_cli(env, "esca", "elenco")
    assert identifier not in again


def test_canary_file_is_planted(env: HostEnvironment, tmp_path: Path) -> None:
    decoy = tmp_path / "secrets" / ".env"
    code, _ = run_cli(env, "canary", "create", "--file", str(decoy), "--lang", "en")
    assert code == 0
    assert decoy.exists()
    assert CANARY_PREFIX in decoy.read_text(encoding="utf-8")


def test_canary_remove_without_id_is_usage_error(env: HostEnvironment) -> None:
    code, _ = run_cli(env, "canary", "remove", "--lang", "en")
    assert code == 2


def test_backup_create_list_and_extract(env: HostEnvironment, tmp_path: Path) -> None:
    run_cli(env, "esca", "crea", "--nota", "seed")
    code, _ = run_cli(env, "copia", "crea")
    assert code == 0
    archives = backup.listing(env.data_dir)
    assert len(archives) == 1
    code, listed = run_cli(env, "copia", "elenco")
    assert code == 0
    assert archives[0].name in listed
    destination = tmp_path / "restore"
    code, _ = run_cli(env, "copia", "estrai", str(archives[0]), str(destination))
    assert code == 0
    assert (destination / "canaries.json").exists()


def test_backup_extract_without_args_is_usage_error(env: HostEnvironment) -> None:
    code, _ = run_cli(env, "backup", "extract", "--lang", "en")
    assert code == 2


def test_backup_list_is_empty_at_first(env: HostEnvironment) -> None:
    code, out = run_cli(env, "backup", "list", "--lang", "en")
    assert code == 0
    assert "No backups yet" in out
