from __future__ import annotations

from pathlib import Path

import pytest

from guardia.safeio import (
    ReadErrorCode,
    SafeReadError,
    decode_text,
    depth_exceeds,
    parse_json,
    parse_toml,
    read_bytes,
    strip_jsonc,
)


def test_strip_jsonc_removes_comments_and_trailing_commas() -> None:
    text = '{\n  // line comment\n  "a": 1, /* block */\n  "b": [1, 2,],\n}\n'
    assert parse_json(text, jsonc=True).value == {"a": 1, "b": [1, 2]}


def test_strip_jsonc_keeps_comment_markers_inside_strings() -> None:
    text = '{"url": "https://example.com//path /* not a comment */", "q": "a\\"//b"}'
    assert parse_json(strip_jsonc(text)).value == {
        "url": "https://example.com//path /* not a comment */",
        "q": 'a"//b',
    }


def test_strip_jsonc_keeps_line_numbers_after_block_comment() -> None:
    text = '{\n/* one\ntwo\n*/\n"a": }'
    with pytest.raises(SafeReadError) as error:
        parse_json(text, jsonc=True)
    assert "line 5" in error.value.detail


def test_unterminated_block_comment_is_a_parse_error() -> None:
    with pytest.raises(SafeReadError) as error:
        strip_jsonc('{"a": 1 /* never closed')
    assert error.value.code is ReadErrorCode.PARSE


def test_strict_json_does_not_accept_comments() -> None:
    with pytest.raises(SafeReadError) as error:
        parse_json('{"a": 1 // comment\n}')
    assert error.value.code is ReadErrorCode.PARSE


def test_duplicate_keys_are_reported() -> None:
    parsed = parse_json('{"a": 1, "a": 2, "b": {"c": 1, "c": 3}}')
    assert parsed.value == {"a": 2, "b": {"c": 3}}
    assert sorted(parsed.duplicate_keys) == ["a", "c"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_standard_constants_are_rejected(constant: str) -> None:
    with pytest.raises(SafeReadError) as error:
        parse_json(f'{{"a": {constant}}}')
    assert error.value.code is ReadErrorCode.PARSE


def test_extremely_deep_json_is_rejected() -> None:
    with pytest.raises(SafeReadError) as error:
        parse_json("[" * 200_000 + "]" * 200_000)
    assert error.value.code is ReadErrorCode.TOO_DEEP


def test_toml_parse_error_is_reported() -> None:
    with pytest.raises(SafeReadError) as error:
        parse_toml("[broken")
    assert error.value.code is ReadErrorCode.PARSE


def test_read_bytes_rejects_files_over_the_limit(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * 11)
    with pytest.raises(SafeReadError) as error:
        read_bytes(path, max_bytes=10)
    assert error.value.code is ReadErrorCode.TOO_LARGE


def test_read_bytes_reports_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SafeReadError) as error:
        read_bytes(tmp_path / "absent.json")
    assert error.value.code is ReadErrorCode.MISSING


def test_read_bytes_rejects_directories(tmp_path: Path) -> None:
    with pytest.raises(SafeReadError) as error:
        read_bytes(tmp_path)
    assert error.value.code is ReadErrorCode.NOT_A_FILE


def test_decode_text_handles_boms() -> None:
    assert decode_text(b"\xef\xbb\xbf{}") == "{}"
    assert decode_text("{}".encode("utf-16")) == "{}"


def test_decode_text_rejects_invalid_utf8() -> None:
    with pytest.raises(SafeReadError) as error:
        decode_text(b"\xff\xff\xffabc"[2:])
    assert error.value.code is ReadErrorCode.DECODE


def test_depth_exceeds() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"k": nested}
    assert depth_exceeds(nested, limit=5)
    assert not depth_exceeds(nested, limit=20)
