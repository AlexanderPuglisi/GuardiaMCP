from __future__ import annotations

import contextlib
import sys
from importlib import resources
from typing import Any

from guardia.app.api import GuardiaApi
from guardia.app.page import build_page
from guardia.app.settings import SettingsStore
from guardia.inventory import HostEnvironment

WINDOW_TITLE = "Guardia MCP"
WINDOW_SIZE = (1280, 820)
MIN_SIZE = (900, 600)
BACKGROUND = "#08080a"
DWM_CORNER_PREFERENCE = 33
DWM_ROUND = 2
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


class NativeWindow:
    def __init__(self, fix_point: Any) -> None:
        self._fix_point = fix_point
        self.window: Any = None

    def minimize(self) -> None:
        self.window.minimize()

    def close(self) -> None:
        self.window.destroy()

    def place(self, x: int, y: int, width: int, height: int) -> None:
        self.window.move(x, y)
        self.window.resize(width, height)

    def resize(self, width: int, height: int, edge: str) -> None:
        vertical = self._fix_point.SOUTH if "n" in edge else self._fix_point.NORTH
        horizontal = self._fix_point.EAST if "w" in edge else self._fix_point.WEST
        self.window.resize(width, height, vertical | horizontal)

    def round_corners(self) -> None:
        if sys.platform != "win32":
            return
        with contextlib.suppress(Exception):
            from webview.platforms import winforms

            set_attribute: Any = winforms.DwmSetWindowAttribute
            set_attribute(self.window.native.Handle.ToInt32(), DWM_CORNER_PREFERENCE, DWM_ROUND)


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
    native = NativeWindow(FixPoint)

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
        background_color=BACKGROUND,
        text_select=True,
        frameless=True,
        easy_drag=False,
        shadow=True,
    )
    native.window.events.shown += native.round_corners
    webview.start(debug=False, private_mode=True, http_server=False, icon=icon_path())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
