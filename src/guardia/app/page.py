from __future__ import annotations

import base64
import hashlib
from importlib import resources

STYLE_MARK = "/*STYLE*/"
SCRIPT_MARK = "/*SCRIPT*/"
CSP_MARK = "CSP_POLICY"


def _resource(name: str) -> str:
    return resources.files("guardia.app").joinpath("web", name).read_text("utf-8")


def csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def content_security_policy(style: str, script: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src {csp_hash(script)}; "
        f"style-src {csp_hash(style)}; "
        "img-src data:; font-src 'none'; connect-src 'none'; media-src 'none'; "
        "object-src 'none'; frame-src 'none'; worker-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )


def build_page(
    template_name: str = "index.html", style_name: str = "app.css", script_name: str = "app.js"
) -> str:
    template = _resource(template_name)
    style = _resource(style_name)
    script = _resource(script_name)
    return (
        template.replace(CSP_MARK, content_security_policy(style, script))
        .replace(STYLE_MARK, style)
        .replace(SCRIPT_MARK, script)
    )
