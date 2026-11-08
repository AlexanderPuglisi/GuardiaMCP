from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from guardia.analysis import AnalysisOptions, analyze
from guardia.app.page import build_page
from guardia.i18n import Translator
from guardia.inventory import HostEnvironment
from guardia.render.html import CONTENT_SECURITY_POLICY, STYLE, render_html
from tests.conftest import WriteJson

WEB = Path(__file__).parent.parent / "src" / "guardia" / "app" / "web"
BIDI = chr(0x202E)
HOSTILE_NAME = '"><img src=x onerror=alert(1)>' + BIDI + "exe"
HOSTILE_ARG = "</style><script>alert(2)</script>"
HOSTILE_DESCRIPTION = (
    "Adds numbers. <svg onload=alert(3)></svg></style><style>body{display:none}</style>"
)
DANGEROUS_TAGS = {
    "script",
    "img",
    "iframe",
    "object",
    "embed",
    "link",
    "base",
    "form",
    "input",
    "a",
}
DANGEROUS_ATTRIBUTES = {"src", "srcset", "href", "xlink:href", "action", "formaction"}
STRICT_APP_DIRECTIVES = {
    "default-src": ["'none'"],
    "img-src": ["data:"],
    "font-src": ["'none'"],
    "connect-src": ["'none'"],
    "media-src": ["'none'"],
    "object-src": ["'none'"],
    "frame-src": ["'none'"],
    "worker-src": ["'none'"],
    "base-uri": ["'none'"],
    "form-action": ["'none'"],
}


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(name for name, _ in attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _directives(policy: str) -> dict[str, list[str]]:
    parts = [part.split() for part in policy.split(";") if part.strip()]
    return {part[0]: part[1:] for part in parts}


def _install_hostile(env: HostEnvironment, write_json: WriteJson) -> None:
    write_json(
        env.app_config / "Claude" / "claude_desktop_config.json",
        {"mcpServers": {HOSTILE_NAME: {"command": "node", "args": [HOSTILE_ARG, "server.js"]}}},
    )
    write_json(
        env.app_config / "Claude" / "Claude Extensions" / "ext.hostile" / "manifest.json",
        {
            "name": "hostile",
            "server": {"mcp_config": {"command": "node", "args": ["${__dirname}/index.js"]}},
            "tools": [{"name": "add", "description": HOSTILE_DESCRIPTION}],
        },
    )


@pytest.mark.parametrize("language", ["it", "en"])
def test_html_report_shows_hostile_names_and_text_only_as_text(
    env: HostEnvironment, write_json: WriteJson, language: str
) -> None:
    _install_hostile(env, write_json)
    report = analyze(env, AnalysisOptions(baseline=False, ledger=False))
    html = render_html(report, Translator(language))
    markup = _Markup()
    markup.feed(html)
    assert not DANGEROUS_TAGS & set(markup.tags)
    assert not [name for name in markup.attributes if name.startswith("on")]
    assert not DANGEROUS_ATTRIBUTES & set(markup.attributes)
    assert html.count("<style") == 1
    assert html.count("</style>") == 1
    assert "onerror=alert(1)" in "".join(markup.text)
    assert BIDI not in html
    assert "\\u202e" in html


def test_html_report_policy_is_exactly_the_strict_one() -> None:
    assert _directives(CONTENT_SECURITY_POLICY) == {
        "default-src": ["'none'"],
        "style-src": ["'unsafe-inline'"],
        "img-src": ["'none'"],
        "script-src": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
    }


@pytest.mark.parametrize(
    "files",
    [("index.html", "app.css", "app.js"), ("confirm.html", "confirm.css", "confirm.js")],
    ids=["main-window", "confirm-window"],
)
def test_app_windows_block_network_fonts_frames_and_inline_code(
    files: tuple[str, str, str],
) -> None:
    page = build_page(*files)
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy
    directives = _directives(policy.group(1))
    for name in ("script-src", "style-src"):
        sources = directives.pop(name)
        assert len(sources) == 1
        assert sources[0].startswith("'sha256-")
    assert directives == STRICT_APP_DIRECTIVES
    assert "unsafe-inline" not in page
    assert "unsafe-eval" not in page


@pytest.mark.parametrize("name", ["app.css", "confirm.css", "report"])
def test_stylesheets_load_nothing_from_outside(name: str) -> None:
    css = STYLE if name == "report" else (WEB / name).read_text(encoding="utf-8")
    for forbidden in ("@import", "url(", "http:", "https:", "@font-face"):
        assert forbidden not in css, (name, forbidden)
