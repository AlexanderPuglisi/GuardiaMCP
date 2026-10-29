from __future__ import annotations

from pathlib import Path

from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR


def test_empty_ledger_is_not_tampering(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "data", RAW_PROTECTOR)
    verification = ledger.verify()
    assert verification.intact
    assert not verification.tampered
