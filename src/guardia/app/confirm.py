from __future__ import annotations

import threading
from typing import Any

from guardia.app.main import HARDENED_SETTINGS, NativeWindow, icon_path
from guardia.app.page import build_page
from guardia.i18n import Translator, load_messages
from guardia.shield.confirm import Answer, ConfirmRequest

WINDOW_SIZE = (500, 470)
BACKGROUND = "#08080a"
TIMER_MARGIN_SECONDS = 3
ACCEPTED = frozenset({Answer.ALLOW, Answer.ALLOW_REMEMBER, Answer.BLOCK, Answer.TIMEOUT})


def confirm_strings(t: Translator) -> dict[str, str]:
    messages = load_messages(t.language)
    return {key[8:]: value for key, value in messages.items() if key.startswith("confirm.")}


class ConfirmApi:
    def __init__(self, request: ConfirmRequest, t: Translator) -> None:
        self._request = request
        self._t = t
        self._result: Answer | None = None
        self._window: Any = None
        self._lock = threading.Lock()

    def details(self) -> dict[str, Any]:
        request = self._request
        return {
            "server": request.server,
            "tool": request.tool,
            "method": request.method,
            "reasons": list(request.reasons),
            "details": request.details,
            "seconds": request.seconds,
            "language": request.language,
            "ui": confirm_strings(self._t),
        }

    def answer(self, choice: object) -> None:
        try:
            chosen = Answer(choice) if isinstance(choice, str) else Answer.BLOCK
        except ValueError:
            chosen = Answer.BLOCK
        with self._lock:
            if self._result is not None:
                return
            self._result = chosen if chosen in ACCEPTED else Answer.BLOCK
        if self._window is not None:
            self._window.destroy()


def show_confirmation(request: ConfirmRequest) -> Answer:
    import webview
    from webview.window import FixPoint

    for key, value in HARDENED_SETTINGS.items():
        webview.settings[key] = value
    t = Translator(request.language)
    api = ConfirmApi(request, t)
    native = NativeWindow(FixPoint)
    native.window = webview.create_window(
        t("confirm.window_title"),
        html=build_page("confirm.html", "confirm.css", "confirm.js"),
        js_api=api,
        width=WINDOW_SIZE[0],
        height=WINDOW_SIZE[1],
        resizable=False,
        frameless=True,
        easy_drag=False,
        shadow=True,
        on_top=True,
        focus=True,
        background_color=BACKGROUND,
    )
    api._window = native.window
    native.window.events.shown += native.round_corners
    timer = threading.Timer(request.seconds + TIMER_MARGIN_SECONDS, api.answer, ("timeout",))
    timer.daemon = True
    timer.start()
    webview.start(debug=False, private_mode=True, http_server=False, icon=icon_path())
    timer.cancel()
    return api._result or Answer.TIMEOUT
