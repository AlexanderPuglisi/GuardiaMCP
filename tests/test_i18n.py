from __future__ import annotations

import pytest

from guardia.i18n import SUPPORTED_LANGUAGES, Translator, detect_language, load_messages


def test_all_languages_define_the_same_keys() -> None:
    reference = set(load_messages("en"))
    for language in SUPPORTED_LANGUAGES:
        assert set(load_messages(language)) == reference, language


def test_explicit_language_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIA_LANG", "en")
    assert detect_language("it") == "it"


def test_environment_variable_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARDIA_LANG", "it")
    assert detect_language(None) == "it"


def test_windows_locale_name_is_recognized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIA_LANG", raising=False)
    monkeypatch.setattr("locale.getlocale", lambda: ("Italian_Italy", "1252"))
    assert detect_language(None) == "it"


def test_unknown_locale_falls_back_to_english(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GUARDIA_LANG", raising=False)
    monkeypatch.setattr("locale.getlocale", lambda: ("ja_JP", "UTF-8"))
    assert detect_language(None) == "en"


def test_translator_formats_and_tolerates_missing_values() -> None:
    t = Translator("it")
    assert t("inventory.saved", path="x.json") == "Risultato salvato in: x.json"
    assert t("inventory.saved") == "Risultato salvato in: {path}"
    assert t("no.such.key") == "no.such.key"
