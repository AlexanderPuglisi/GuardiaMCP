from __future__ import annotations

import contextlib
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from guardia.app.api import GuardiaApi
from guardia.app.page import build_page
from guardia.app.settings import SettingsStore
from guardia.app.window_state import (
    Rect,
    WindowState,
    fit,
    load_state,
    save_state,
    too_small,
)
from guardia.inventory import HostEnvironment

WINDOW_TITLE = "Guardia MCP"
WINDOW_SIZE = (1280, 820)
MIN_SIZE = (900, 600)
BACKGROUND = "#08080a"
DWM_CORNER_PREFERENCE = 33
DWM_ROUND = 2
DWM_SQUARE = 1
DEFAULT_DPI = 96
CREATE_TIMEOUT_SECONDS = 15
HARDENED_SETTINGS: dict[str, Any] = {
    "ALLOW_DOWNLOADS": False,
    "OPEN_DEVTOOLS_IN_DEBUG": False,
    "SHOW_DEFAULT_MENUS": False,
    "REMOTE_DEBUGGING_PORT": None,
    "IGNORE_SSL_ERRORS": False,
    "DRAG_REGION_SELECTOR": ".pywebview-drag-region",
    "DRAG_REGION_DIRECT_TARGET_ONLY": True,
}


def icon_path() -> str:
    return str(resources.files("guardia.app").joinpath("guardia.ico"))


def _winforms() -> Any:
    from webview.platforms import winforms

    return winforms


def _rect(bounds: Any) -> Rect:
    return Rect(int(bounds.X), int(bounds.Y), int(bounds.Width), int(bounds.Height))


class NativeWindow:
    def __init__(self, fix_point: Any, directory: Path | None = None) -> None:
        self._fix_point = fix_point
        self._directory = directory
        self._restore_bounds: Rect | None = None
        self.maximized = False
        self.window: Any = None

    def minimize(self) -> None:
        self.window.minimize()

    def close(self) -> None:
        self.remember()
        self.window.destroy()

    def _apply(self, bounds: Rect) -> None:
        self.window.native.SetBounds(bounds.x, bounds.y, bounds.width, bounds.height)

    def _invoke(self, action: Any) -> None:
        forms = _winforms()
        self.window.native.Invoke(forms.Func[forms.Type](action))

    def _work_area(self, near: Rect | None) -> Rect:
        forms = _winforms()
        screen = forms.WinForms.Screen
        if near is None:
            found = screen.FromPoint(forms.WinForms.Cursor.Position)
        else:
            found = screen.FromPoint(forms.Point(near.x + near.width // 2, near.y + 10))
        return _rect(found.WorkingArea)

    def maximize(self) -> None:
        if sys.platform != "win32":
            self.window.maximize()
            self.maximized = True
            return

        def fill() -> None:
            self._restore_bounds = _rect(self.window.native.Bounds)
            self._apply(self._work_area(self._restore_bounds))

        self._invoke(fill)
        self.maximized = True
        self._corners(DWM_SQUARE)

    def restore(self) -> None:
        if sys.platform != "win32":
            self.window.restore()
            self.maximized = False
            return
        saved = self._restore_bounds

        def back() -> None:
            if saved is not None:
                self._apply(saved)

        self._invoke(back)
        self.maximized = False
        self._corners(DWM_ROUND)

    def place(self, state: WindowState) -> None:
        self.window.events.before_show.wait(CREATE_TIMEOUT_SECONDS)
        if sys.platform != "win32" or self.window.native is None:
            self.window.show()
            return

        def arrange() -> None:
            form = self.window.native
            scale = max(int(getattr(form, "DeviceDpi", DEFAULT_DPI)), DEFAULT_DPI) / DEFAULT_DPI
            area = self._work_area(state.bounds)
            default = (round(WINDOW_SIZE[0] * scale), round(WINDOW_SIZE[1] * scale))
            minimum = (round(MIN_SIZE[0] * scale), round(MIN_SIZE[1] * scale))
            normal = fit(area, state.bounds, default)
            self._restore_bounds = normal
            if self.maximized or too_small(area, minimum):
                self.maximized = True
                self._apply(area)
            else:
                self._apply(normal)

        with contextlib.suppress(Exception):
            self._invoke(arrange)
        self._corners(DWM_SQUARE if self.maximized else DWM_ROUND)
        self.window.show()

    def remember(self) -> None:
        if self._directory is None or sys.platform != "win32":
            return
        with contextlib.suppress(Exception):
            form = self.window.native
            normal = form.Bounds if str(form.WindowState) == "Normal" else form.RestoreBounds
            bounds = self._restore_bounds if self.maximized else _rect(normal)
            save_state(self._directory, WindowState(maximized=self.maximized, bounds=bounds))

    def resize(self, width: int, height: int, edge: str) -> None:
        vertical = self._fix_point.SOUTH if "n" in edge else self._fix_point.NORTH
        horizontal = self._fix_point.EAST if "w" in edge else self._fix_point.WEST
        self.window.resize(width, height, vertical | horizontal)

    def round_corners(self) -> None:
        self._corners(DWM_SQUARE if self.maximized else DWM_ROUND)

    def _corners(self, preference: int) -> None:
        if sys.platform != "win32":
            return
        with contextlib.suppress(Exception):
            from webview.platforms import winforms

            set_attribute: Any = winforms.DwmSetWindowAttribute
            set_attribute(self.window.native.Handle.ToInt32(), DWM_CORNER_PREFERENCE, preference)


def main() -> int:
    try:
        import webview
        from webview.window import FixPoint
    except ImportError:
        sys.stderr.write(
            "The desktop app needs pywebview: uv sync --extra app\n"
            "L'app desktop richiede pywebview: uv sync --extra app\n"
        )
        return 2
    for key, value in HARDENED_SETTINGS.items():
        webview.settings[key] = value
    env = HostEnvironment.from_os()
    native = NativeWindow(FixPoint, env.data_dir)
    state = load_state(env.data_dir)
    native.maximized = state.maximized

    def save_dialog(filename: str) -> str | None:
        result = native.window.create_file_dialog(webview.FileDialog.SAVE, save_filename=filename)
        if not result:
            return None
        return str(result if isinstance(result, str) else result[0])

    def folder_dialog() -> str | None:
        result = native.window.create_file_dialog(webview.FileDialog.FOLDER)
        return str(result[0]) if result else None

    api = GuardiaApi(
        env,
        SettingsStore(env.data_dir),
        save_dialog=save_dialog,
        folder_dialog=folder_dialog,
        window=native,
    )
    native.window = webview.create_window(
        WINDOW_TITLE,
        html=build_page(),
        js_api=api,
        width=WINDOW_SIZE[0],
        height=WINDOW_SIZE[1],
        min_size=MIN_SIZE,
        hidden=sys.platform == "win32",
        background_color=BACKGROUND,
        text_select=True,
        frameless=True,
        easy_drag=False,
        shadow=True,
    )
    native.window.events.shown += native.round_corners
    native.window.events.closing += native.remember
    webview.start(
        native.place,
        (state,),
        debug=False,
        private_mode=True,
        http_server=False,
        icon=icon_path(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
