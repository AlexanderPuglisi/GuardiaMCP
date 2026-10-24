from __future__ import annotations

import re
from pathlib import Path

from guardia.app.api import GuardiaApi
from guardia.app.page import build_page
from guardia.app.settings import SettingsStore
from guardia.i18n import load_messages
from guardia.inventory import HostEnvironment

WEB = Path(__file__).parent.parent / "src" / "guardia" / "app" / "web"
SCRIPT = (WEB / "app.js").read_text(encoding="utf-8")


def called_methods(script: str) -> set[str]:
    names: set[str] = set()
    for args in re.findall(r"\b(?:call|shieldAction|changeSetting)\(([^()]*)", script):
        first = re.sub(r'[\w.]+ === "[^"]*"', "", args.split(",")[0])
        names |= set(re.findall(r'"([a-z_]+)"', first))
    return names | set(re.findall(r"\.api\.([a-z_]+)\(", script))


def test_page_calls_only_methods_the_api_has(env: HostEnvironment) -> None:
    api = GuardiaApi(env, SettingsStore(env.data_dir))
    public = {name for name in dir(api) if not name.startswith("_")}
    called = called_methods(SCRIPT)
    assert {"state", "shield_rules_template", "shield_rules_save", "window_resize"} <= called
    assert called <= public, called - public


def test_page_asks_inside_the_window_never_with_browser_dialogs() -> None:
    assert re.search(r"\b(?:confirm|alert|prompt)\(", SCRIPT) is None
    assert '"alertdialog"' in SCRIPT


def test_confirm_window_says_what_is_remembered() -> None:
    script = (WEB / "confirm.js").read_text(encoding="utf-8")
    assert "ui.remember_method" in script
    for language in ("it", "en"):
        messages = load_messages(language)
        assert messages["confirm.remember_method"] != messages["confirm.remember"]


def css_rules(css: str, selector: str) -> list[str]:
    return [
        body
        for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css)
        if selector in [part.strip() for part in selectors.split(",")]
    ]


def test_glow_travels_along_the_edge_in_every_window_state() -> None:
    for name in ("app.css", "confirm.css"):
        css = (WEB / name).read_text(encoding="utf-8")
        light = " ".join(css_rules(css, ".glow i"))
        assert "offset-path: inset(" in light, name
        assert "animation: glow-orbit" in light, name
        assert "display: none" not in light, name
        keyframes = re.search(r"@keyframes glow-orbit \{(.*?)\}\s*\}", css, re.DOTALL)
        assert keyframes is not None, name
        assert "offset-distance: 0%" in keyframes.group(1)
        assert "offset-distance: 100%" in keyframes.group(1)
    css = (WEB / "app.css").read_text(encoding="utf-8")
    assert all("display: none" not in body for body in css_rules(css, ".maximized .glow"))
    assert all("display: none" not in body for body in css_rules(css, ".maximized .glow i"))
    assert "display: none" in " ".join(css_rules(css, '[data-glow="off"] .glow i'))
    page = build_page()
    assert page.count('<div class="glow" aria-hidden="true"><i></i><i></i></div>') == 1


def test_page_explains_a_program_that_does_not_answer() -> None:
    page = build_page()
    assert 'id="boot"' in page
    assert page.count("Alt+F4") == 2
    source = (WEB.parent / "main.py").read_text(encoding="utf-8")
    assert "zoomable=True" in source
