from __future__ import annotations

import unicodedata

_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def is_hidden_char(char: str) -> bool:
    return unicodedata.category(char) in _HIDDEN_CATEGORIES


def safe_text(value: str, max_length: int | None = None) -> str:
    out: list[str] = []
    for char in value:
        if char == "\t":
            out.append("\\t")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif is_hidden_char(char):
            code = ord(char)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            out.append(char)
    text = "".join(out)
    if max_length is not None and len(text) > max_length:
        return text[: max(max_length - 1, 0)] + "…"
    return text
