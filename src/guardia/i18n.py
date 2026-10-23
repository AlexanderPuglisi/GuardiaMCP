from __future__ import annotations

import functools
import locale
import os
import tomllib
from importlib import resources
from typing import Any

SUPPORTED_LANGUAGES = ("it", "en")
DEFAULT_LANGUAGE = "en"


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    for key, value in data.items():
        full_key = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, full_key + "."))
        else:
            flat[full_key] = str(value)
    return flat


@functools.cache
def load_messages(language: str) -> dict[str, str]:
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"unsupported language: {language}")
    text = resources.files("guardia").joinpath("locales", f"{language}.toml").read_text("utf-8")
    return _flatten(tomllib.loads(text))


def _normalize(value: str | None) -> str | None:
    if not value:
        return None
    short = value.strip().lower()[:2]
    if short in SUPPORTED_LANGUAGES:
        return short
    if value.strip().lower().startswith("italian"):
        return "it"
    return None


def detect_language(explicit: str | None = None) -> str:
    for candidate in (explicit, os.environ.get("GUARDIA_LANG")):
        normalized = _normalize(candidate)
        if normalized:
            return normalized
    system = _normalize(locale.getlocale()[0])
    return system or DEFAULT_LANGUAGE


class Translator:
    def __init__(self, language: str) -> None:
        self.language = language
        self._messages = load_messages(language)
        self._fallback = load_messages(DEFAULT_LANGUAGE)

    def has(self, key: str) -> bool:
        return key in self._messages or key in self._fallback

    def __call__(self, key: str, /, **values: object) -> str:
        template = self._messages.get(key) or self._fallback.get(key) or key
        try:
            return template.format_map(values)
        except (KeyError, IndexError, ValueError):
            return template
