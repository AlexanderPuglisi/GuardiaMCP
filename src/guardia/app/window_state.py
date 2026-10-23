from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from guardia.ledger import write_atomic
from guardia.model import canonical_json
from guardia.safeio import SafeReadError, parse_json, read_text

WINDOW_FILE = "app-window.json"
MAX_COORDINATE = 100_000
MIN_EDGE = 200
VISIBLE_PART = 120
NORMAL_SHARE = 0.9


@dataclass(frozen=True, slots=True)
class Rect:
    x: int
    y: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height


@dataclass(frozen=True, slots=True)
class WindowState:
    maximized: bool = True
    bounds: Rect | None = None


def _number(value: object, low: int, high: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    number = round(value)
    return number if low <= number <= high else None


def _rect(document: object) -> Rect | None:
    if not isinstance(document, dict):
        return None
    x = _number(document.get("x"), -MAX_COORDINATE, MAX_COORDINATE)
    y = _number(document.get("y"), -MAX_COORDINATE, MAX_COORDINATE)
    width = _number(document.get("width"), MIN_EDGE, MAX_COORDINATE)
    height = _number(document.get("height"), MIN_EDGE, MAX_COORDINATE)
    if x is None or y is None or width is None or height is None:
        return None
    return Rect(x, y, width, height)


def load_state(directory: Path) -> WindowState:
    try:
        document = parse_json(read_text(directory / WINDOW_FILE, 16 * 1024)).value
    except SafeReadError:
        return WindowState()
    if not isinstance(document, dict):
        return WindowState()
    maximized = document.get("maximized")
    return WindowState(
        maximized=maximized if isinstance(maximized, bool) else True,
        bounds=_rect(document.get("bounds")),
    )


def save_state(directory: Path, state: WindowState) -> None:
    bounds = state.bounds
    document: dict[str, object] = {"maximized": state.maximized}
    if bounds is not None:
        document["bounds"] = {
            "x": bounds.x,
            "y": bounds.y,
            "width": bounds.width,
            "height": bounds.height,
        }
    directory.mkdir(parents=True, exist_ok=True)
    write_atomic(directory / WINDOW_FILE, canonical_json(document))


def visible_in(window: Rect, area: Rect) -> bool:
    across = min(window.right, area.right) - max(window.x, area.x)
    title_inside = area.y <= window.y <= area.bottom - VISIBLE_PART
    return across >= VISIBLE_PART and title_inside


def fit(area: Rect, wanted: Rect | None, default: tuple[int, int]) -> Rect:
    if wanted is None:
        width = min(default[0], round(area.width * NORMAL_SHARE))
        height = min(default[1], round(area.height * NORMAL_SHARE))
    else:
        width = min(wanted.width, area.width)
        height = min(wanted.height, area.height)
    if wanted is None or not visible_in(wanted, area):
        return Rect(
            area.x + (area.width - width) // 2,
            area.y + (area.height - height) // 2,
            width,
            height,
        )
    x = min(max(wanted.x, area.x), area.right - width)
    y = min(max(wanted.y, area.y), area.bottom - height)
    return Rect(x, y, width, height)


def too_small(area: Rect, minimum: tuple[int, int]) -> bool:
    return area.width < minimum[0] or area.height < minimum[1]
