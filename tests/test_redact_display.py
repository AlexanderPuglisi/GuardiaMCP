from __future__ import annotations

import pytest

from guardia.display import safe_text
from guardia.redact import REDACTED, is_secret_name, redact_args, redact_text, redact_url

GITHUB_TOKEN = "ghp_" + "a1B2" * 9
ANTHROPIC_KEY = "sk-ant-api03-" + "x" * 30


def test_flag_followed_by_secret_value_is_redacted() -> None:
    assert redact_args(["--api-key", "abc123", "--verbose"]) == ("--api-key", REDACTED, "--verbose")


def test_assignment_with_secret_name_is_redacted() -> None:
    assert redact_args(["--token=xyz", "API_KEY=abc", "PORT=8080"]) == (
        f"--token={REDACTED}",
        f"API_KEY={REDACTED}",
        "PORT=8080",
    )


def test_known_token_formats_are_redacted_anywhere() -> None:
    assert redact_args([GITHUB_TOKEN]) == (REDACTED,)
    assert redact_text(f"Bearer {ANTHROPIC_KEY}") == f"Bearer {REDACTED}"


def test_ordinary_arguments_are_untouched() -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\Documents"]
    assert redact_args(args) == tuple(args)


def test_url_credentials_and_secret_query_values_are_redacted() -> None:
    url = "https://user:pw@mcp.example.com/sse?key=K&api_key=SECRET&page=2#top"
    assert redact_url(url) == (
        f"https://{REDACTED}@mcp.example.com/sse?key={REDACTED}&api_key={REDACTED}&page=2#top"
    )


def test_url_arguments_are_redacted() -> None:
    assert redact_args(["--url", "https://h.example/?token=abc"]) == (
        "--url",
        f"https://h.example/?token={REDACTED}",
    )


def test_url_without_query_is_unchanged() -> None:
    assert redact_url("https://mcp.example.com/mcp") == "https://mcp.example.com/mcp"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("GITHUB_TOKEN", True),
        ("OPENAI_API_KEY", True),
        ("password", True),
        ("Authorization", True),
        ("key", True),
        ("PORT", False),
        ("ROOT_DIR", False),
    ],
)
def test_is_secret_name(name: str, expected: bool) -> None:
    assert is_secret_name(name) is expected


def test_safe_text_neutralizes_terminal_escape_sequences() -> None:
    assert safe_text("ok\x1b[2Jbad") == "ok\\u001b[2Jbad"


def test_safe_text_reveals_invisible_and_bidi_characters() -> None:
    assert safe_text("a\u200bb") == "a\\u200bb"
    assert safe_text("x\u202ey") == "x\\u202ey"
    assert safe_text("t\U000e0041") == "t\\U000e0041"


def test_safe_text_escapes_newlines_and_truncates() -> None:
    assert safe_text("a\nb") == "a\\nb"
    assert safe_text("abcdefgh", max_length=5) == "abcd…"


def test_safe_text_keeps_accented_letters() -> None:
    assert safe_text("perché è così") == "perché è così"
