from __future__ import annotations

from pathlib import Path

import pytest

from guardia.app.window_state import (
    WINDOW_FILE,
    Rect,
    WindowState,
    fit,
    load_state,
    save_state,
    too_small,
    visible_in,
)

FULL_HD = Rect(0, 0, 1920, 1032)
LAPTOP_150 = Rect(0, 0, 1920, 1032)
SMALL = Rect(0, 0, 1366, 728)
SECOND = Rect(1920, 0, 2560, 1392)


def inside(window: Rect, area: Rect) -> bool:
    return (
        area.x <= window.x
        and area.y <= window.y
        and window.right <= area.right
        and window.bottom <= area.bottom
    )


@pytest.mark.parametrize("area", [FULL_HD, SMALL, SECOND, Rect(-1280, 0, 1280, 984)])
def test_first_start_is_centered_and_never_larger_than_the_screen(area: Rect) -> None:
    window = fit(area, None, (1920, 1230))
    assert inside(window, area)
    assert window.width <= area.width * 0.9 + 1
    assert window.height <= area.height * 0.9 + 1
    assert abs((window.x - area.x) - (area.right - window.right)) <= 1


def test_default_size_is_kept_when_it_fits() -> None:
    assert fit(FULL_HD, None, (1280, 820)) == Rect(320, 106, 1280, 820)


def test_saved_position_is_kept_when_visible() -> None:
    saved = Rect(2000, 100, 1400, 900)
    assert fit(SECOND, saved, (1280, 820)) == saved


@pytest.mark.parametrize(
    "saved",
    [
        Rect(5000, 5000, 1280, 820),
        Rect(-3000, 100, 1280, 820),
        Rect(100, -500, 1280, 820),
        Rect(100, 1000, 1280, 820),
    ],
)
def test_window_lost_off_screen_comes_back_centered(saved: Rect) -> None:
    window = fit(LAPTOP_150, saved, (1280, 820))
    assert inside(window, LAPTOP_150)
    assert window.x == (LAPTOP_150.width - window.width) // 2


def test_window_saved_on_a_bigger_monitor_shrinks_to_fit() -> None:
    window = fit(SMALL, Rect(10, 10, 2400, 1300), (1280, 820))
    assert inside(window, SMALL)
    assert (window.width, window.height) == (SMALL.width, SMALL.height)


def test_partly_visible_window_is_pulled_inside() -> None:
    window = fit(FULL_HD, Rect(1500, 300, 1280, 820), (1280, 820))
    assert window == Rect(640, 212, 1280, 820)


def test_visibility_needs_the_title_bar_on_screen() -> None:
    assert visible_in(Rect(100, 100, 800, 600), FULL_HD)
    assert not visible_in(Rect(100, -50, 800, 600), FULL_HD)
    assert not visible_in(Rect(1850, 100, 800, 600), FULL_HD)


def test_tiny_screens_start_maximized() -> None:
    assert too_small(Rect(0, 0, 1280, 680), (1350, 900))
    assert not too_small(FULL_HD, (900, 600))


def test_state_round_trip_and_first_start(tmp_path: Path) -> None:
    assert load_state(tmp_path) == WindowState(maximized=True, bounds=None)
    state = WindowState(maximized=False, bounds=Rect(-1200, 40, 1100, 700))
    save_state(tmp_path, state)
    assert load_state(tmp_path) == state


@pytest.mark.parametrize(
    ("content", "maximized"),
    [
        ("not json", True),
        ("[]", True),
        ('{"maximized": "yes"}', True),
        ('{"maximized": false, "bounds": {"x": 1, "y": 2, "width": 10, "height": 900}}', False),
        ('{"maximized": false, "bounds": {"x": 1e999, "y": 2, "width": 900, "height": 900}}', True),
        ('{"maximized": false, "bounds": {"x": true, "y": 2, "width": 900, "height": 900}}', False),
        ('{"maximized": false, "bounds": "big"}', False),
    ],
)
def test_damaged_state_falls_back_safely(tmp_path: Path, content: str, maximized: bool) -> None:
    (tmp_path / WINDOW_FILE).write_text(content, encoding="utf-8")
    assert load_state(tmp_path) == WindowState(maximized=maximized, bounds=None)
