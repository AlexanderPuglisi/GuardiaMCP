from __future__ import annotations

import argparse
import io
import json
import tempfile
from pathlib import Path
from typing import Any

import demo
from PIL import Image

from guardia.app.api import GuardiaApi
from guardia.app.confirm import confirm_strings
from guardia.app.page import CSP_MARK, SCRIPT_MARK, STYLE_MARK, content_security_policy
from guardia.app.settings import SettingsStore
from guardia.cli import main as cli_main
from guardia.i18n import Translator

TARGET = demo.PROJECT / "docs" / "tutorial"
SHOTS = (
    ("01-overview", "overview", 800),
    ("02-findings", "findings", 800),
    ("03-finding-detail", "inventory:github", 800),
    ("04-shield", "shield", 800),
    ("05-rules-editor", "shield:editor", 1000),
    ("06-settings", "settings", 1240),
    ("07-ledger", "ledger", 800),
)
CONFIRM_SIZE = (500, 470)
CONFIRM_STUB = """"use strict";
window.pywebview = { api: {
  details: async () => (__DETAILS__),
  answer: async () => null,
} };
"""


def history(env: Any, language: str, project: Path) -> list[dict[str, Any]]:
    api = GuardiaApi(env, SettingsStore(env.data_dir), folder_dialog=lambda: str(project))
    api.set_language(language)
    api.set_option("skills", False)
    api.set_option("skills", True)
    api.add_project()
    items: list[dict[str, Any]] = api.settings_history()["items"]
    return items


def confirm_page(language: str) -> str:
    details = {
        "server": "github",
        "tool": "delete_repo",
        "method": "tools/call",
        "reasons": [
            "GitHub: chiedi prima di cancellare"
            if language == "it"
            else "GitHub: ask before deleting"
        ],
        "details": '{"repo": "demo/notes"}',
        "seconds": 60,
        "language": language,
        "ui": confirm_strings(Translator(language)),
    }
    template = (demo.WEB / "confirm.html").read_text(encoding="utf-8")
    style = (demo.WEB / "confirm.css").read_text(encoding="utf-8")
    payload = json.dumps(details, ensure_ascii=True).replace("<", "\\u003c")
    script = CONFIRM_STUB.replace("__DETAILS__", payload) + (demo.WEB / "confirm.js").read_text(
        encoding="utf-8"
    )
    return (
        template.replace(CSP_MARK, content_security_policy(style, script))
        .replace(STYLE_MARK, style)
        .replace(SCRIPT_MARK, script)
    )


def shoot(page: Path, view: str, target: Path, profile: Path, height: int) -> None:
    demo.SHOT_SIZE = (demo.SHOT_SIZE[0], height)
    demo.capture(page, view, target, profile)
    with Image.open(target) as image:
        image.convert("RGB").save(target, optimize=True)


def build(language: str) -> None:
    TARGET.mkdir(parents=True, exist_ok=True)
    width = demo.SHOT_SIZE[0]
    with tempfile.TemporaryDirectory(
        prefix="guardia-tutorial-", ignore_cleanup_errors=True
    ) as temporary:
        root = Path(temporary)
        env = demo.demo_environment(root / "pc")
        demo.install_extension(env, "Adds two numbers.")
        GuardiaApi(env, SettingsStore(env.data_dir)).scan()
        demo.install_extension(env, demo.POISON)
        demo.shield_history(env)
        cli_main(["scansiona"], env=env, stdout=io.StringIO())
        scrub = demo.scrubber(root / "pc")
        project = env.home / "progetti" / "notes-app"
        project.mkdir(parents=True, exist_ok=True)
        data = demo.record(env, language, scrub)
        data["history"] = scrub(history(env, language, project))
        data["state"]["settings"]["projects"] = scrub([str(project)])
        page = root / "app.html"
        page.write_text(demo.demo_page(data), encoding="utf-8")
        editable = dict(
            data, shield=dict(data["shield"], rules=dict(data["shield"]["rules"], exists=True))
        )
        editor = root / "editor.html"
        editor.write_text(demo.demo_page(editable), encoding="utf-8")
        for name, view, height in SHOTS:
            source = editor if view == "shield:editor" else page
            shoot(source, view, TARGET / f"{language}-{name}.png", root / "profile", height)
        confirm = root / "confirm.html"
        confirm.write_text(confirm_page(language), encoding="utf-8")
        demo.SHOT_SIZE = CONFIRM_SIZE
        demo.capture(confirm, "", TARGET / f"{language}-08-confirm.png", root / "profile")
        demo.SHOT_SIZE = (width, 800)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the tutorial screenshots from fake data.")
    parser.add_argument("--lang", choices=("it", "en"), action="append")
    args = parser.parse_args()
    for language in args.lang or ["it", "en"]:
        build(language)
        print(language)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
