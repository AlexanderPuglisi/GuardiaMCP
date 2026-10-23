from __future__ import annotations

import sys
from typing import Any

from guardia.app.api import GuardiaApi
from guardia.app.page import build_page
from guardia.app.settings import SettingsStore
from guardia.inventory import HostEnvironment

WINDOW_TITLE = "Guardia MCP"
WINDOW_SIZE = (1280, 820)
MIN_SIZE = (900, 600)
BACKGROUND = "#08080a"
HARDENED_SETTINGS: dict[str, Any] = {
    "ALLOW_DOWNLOADS": False,
    "OPEN_DEVTOOLS_IN_DEBUG": False,
    "SHOW_DEFAULT_MENUS": False,
    "REMOTE_DEBUGGING_PORT": None,
    "IGNORE_SSL_ERRORS": False,
}


def main() -> int:
    try:
        import webview
    except ImportError:
        sys.stderr.write(
            "The desktop app needs pywebview: uv sync --extra app\n"
            "L'app desktop richiede pywebview: uv sync --extra app\n"
        )
        return 2
    for key, value in HARDENED_SETTINGS.items():
        webview.settings[key] = value
    env = HostEnvironment.from_os()
    holder: dict[str, Any] = {}

    def save_dialog(filename: str) -> str | None:
        result = holder["window"].create_file_dialog(
            webview.FileDialog.SAVE, save_filename=filename
        )
        if not result:
            return None
        return str(result if isinstance(result, str) else result[0])

    def folder_dialog() -> str | None:
        result = holder["window"].create_file_dialog(webview.FileDialog.FOLDER)
        return str(result[0]) if result else None

    api = GuardiaApi(
        env,
        SettingsStore(env.data_dir),
        save_dialog=save_dialog,
        folder_dialog=folder_dialog,
    )
    holder["window"] = webview.create_window(
        WINDOW_TITLE,
        html=build_page(),
        js_api=api,
        width=WINDOW_SIZE[0],
        height=WINDOW_SIZE[1],
        min_size=MIN_SIZE,
        background_color=BACKGROUND,
        text_select=True,
    )
    webview.start(debug=False, private_mode=True, http_server=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
