from __future__ import annotations

import contextlib
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from guardia.i18n import SUPPORTED_LANGUAGES
from guardia.model import canonical_json
from guardia.safeio import SafeReadError, parse_json, read_text

SETTINGS_FILE = "app-settings.json"
MAX_PROJECTS = 50
MAX_PATH_LENGTH = 1024
BOOLEAN_OPTIONS = ("skills", "tools", "baseline")


@dataclass(frozen=True, slots=True)
class AppSettings:
    language: str = "it"
    skills: bool = True
    tools: bool = True
    baseline: bool = True
    projects: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "skills": self.skills,
            "tools": self.tools,
            "baseline": self.baseline,
            "projects": list(self.projects),
        }


def validate_language(value: object) -> str:
    if not isinstance(value, str) or value not in SUPPORTED_LANGUAGES:
        raise ValueError("invalid language")
    return value


def validate_project(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH or "\x00" in value:
        raise ValueError("invalid path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("path must be absolute")
    return str(path)


def with_option(settings: AppSettings, name: str, value: bool) -> AppSettings:
    if name == "skills":
        return replace(settings, skills=value)
    if name == "tools":
        return replace(settings, tools=value)
    if name == "baseline":
        return replace(settings, baseline=value)
    raise ValueError("unknown option")


def from_document(document: object) -> AppSettings:
    if not isinstance(document, dict):
        return AppSettings()
    settings = AppSettings()
    language = document.get("language")
    if isinstance(language, str) and language in SUPPORTED_LANGUAGES:
        settings = replace(settings, language=language)
    for option in BOOLEAN_OPTIONS:
        value = document.get(option)
        if isinstance(value, bool):
            settings = with_option(settings, option, value)
    projects = document.get("projects")
    if isinstance(projects, list):
        valid: list[str] = []
        for item in projects[:MAX_PROJECTS]:
            with contextlib.suppress(ValueError):
                valid.append(validate_project(item))
        settings = replace(settings, projects=tuple(dict.fromkeys(valid)))
    return settings


class SettingsStore:
    def __init__(self, directory: Path) -> None:
        self.path = directory / SETTINGS_FILE

    def load(self) -> AppSettings:
        try:
            return from_document(parse_json(read_text(self.path, 256 * 1024)).value)
        except SafeReadError:
            return AppSettings()

    def save(self, settings: AppSettings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=".settings-", dir=self.path.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(canonical_json(settings.to_dict()))
            Path(temporary).replace(self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                Path(temporary).unlink()
            raise
