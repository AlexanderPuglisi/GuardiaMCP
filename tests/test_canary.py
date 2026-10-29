from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from guardia.canary import (
    CANARY_PREFIX,
    CanaryError,
    CanaryStore,
    decoy_text,
    find_canary,
    new_token,
    plant,
)
from guardia.secure_store import RAW_PROTECTOR


def store(tmp_path: Path) -> CanaryStore:
    return CanaryStore(tmp_path / "data", RAW_PROTECTOR)


def test_token_has_prefix_and_is_unique() -> None:
    tokens = {new_token() for _ in range(100)}
    assert len(tokens) == 100
    assert all(token.startswith(CANARY_PREFIX) for token in tokens)


def test_add_then_read_round_trip(tmp_path: Path) -> None:
    keeper = store(tmp_path)
    canary = keeper.add(note="the bait in Documents")
    again = keeper.all()
    assert [item.token for item in again] == [canary.token]
    assert again[0].note == "the bait in Documents"
    assert canary.token in keeper.tokens()


def test_tokens_are_collected(tmp_path: Path) -> None:
    keeper = store(tmp_path)
    first = keeper.add()
    second = keeper.add()
    assert keeper.tokens() == frozenset({first.token, second.token})


def test_remove_by_id(tmp_path: Path) -> None:
    keeper = store(tmp_path)
    first = keeper.add()
    second = keeper.add()
    removed = keeper.remove(first.id)
    assert removed is not None and removed.id == first.id
    assert keeper.tokens() == frozenset({second.token})
    assert keeper.remove("missing") is None


def test_missing_store_is_empty(tmp_path: Path) -> None:
    assert store(tmp_path).all() == []
    assert store(tmp_path).tokens() == frozenset()


def test_unknown_format_is_rejected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    (data / "canaries.json").write_bytes(b"not a guardia file")
    with pytest.raises(CanaryError):
        store(tmp_path).all()


def test_note_is_capped(tmp_path: Path) -> None:
    keeper = store(tmp_path)
    canary = keeper.add(note="x" * 5000)
    assert len(keeper.all()[0].note) <= len(canary.note) <= 200


def test_decoy_contains_the_token() -> None:
    token = new_token()
    assert token in decoy_text(token)


def test_plant_writes_the_decoy(tmp_path: Path) -> None:
    token = new_token()
    target = tmp_path / "secrets" / ".env"
    plant(target, token)
    assert token in target.read_text(encoding="utf-8")


def test_find_canary_in_a_value() -> None:
    token = new_token()
    assert find_canary({"content": [{"text": f"x {token} y"}]}, frozenset({token})) == token


def test_find_canary_in_a_dict_key() -> None:
    token = new_token()
    assert find_canary({token: "exfil"}, frozenset({token})) == token


def test_find_canary_deeply_nested() -> None:
    token = new_token()
    value: Any = token
    for _ in range(200):
        value = {"wrap": value}
    assert find_canary(value, frozenset({token})) == token


def test_find_canary_after_long_filler() -> None:
    token = new_token()
    assert find_canary("A" * 300000 + token, frozenset({token})) == token


def test_find_canary_absent_or_no_tokens() -> None:
    assert find_canary({"a": ["b", "c"]}, frozenset({new_token()})) is None
    assert find_canary({"a": "b"}, frozenset()) is None
