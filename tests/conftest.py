from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from guardia.inventory import HostEnvironment

WriteJson = Callable[[Path, object], Path]
WriteText = Callable[[Path, str], Path]


@pytest.fixture
def env(tmp_path: Path) -> HostEnvironment:
    environment = HostEnvironment.for_root(tmp_path)
    environment.home.mkdir(parents=True)
    environment.cwd.mkdir(parents=True)
    return environment


@pytest.fixture
def write_text() -> WriteText:
    def write(path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    return write


@pytest.fixture
def write_json(write_text: WriteText) -> WriteJson:
    def write(path: Path, data: object) -> Path:
        return write_text(path, json.dumps(data, indent=2))

    return write
