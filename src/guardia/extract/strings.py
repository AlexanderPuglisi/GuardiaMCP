from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from urllib.parse import urlsplit

from guardia.model import SignalKind
from guardia.redact import SECRET_VALUE, redact_text
from guardia.scanner.checks import TUNNEL_DOMAINS, URL_IN_TEXT

MAX_LITERAL_LENGTH = 20_000

CREDENTIAL_PATHS = re.compile(
    r"(\.ssh[/\\]|[/\\]\.ssh\b|^\.ssh$|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\]credentials"
    r"|\.git-credentials|\.docker[/\\]config\.json|\.kube[/\\]config|\blogin data\b"
    r"|cookies\.sqlite|\bkey4\.db\b|\blogins\.json\b|wallet\.dat|[/\\](electrum|exodus)[/\\]"
    r"|\.gnupg\b|/etc/shadow\b|\.netrc\b|\.pgpass\b)",
    re.IGNORECASE,
)
AGENT_CONFIGS = re.compile(
    r"(claude_desktop_config\.json|\.claude\.json|\.cursor[/\\]mcp\.json|mcp_config\.json"
    r"|\.codex[/\\]config\.toml|\.gemini[/\\]settings\.json|managed-mcp\.json)",
    re.IGNORECASE,
)


def _public_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_global


def classify(value: str) -> Iterator[tuple[SignalKind, str, str]]:
    if not value or len(value) > MAX_LITERAL_LENGTH:
        return
    match = CREDENTIAL_PATHS.search(value)
    if match:
        yield SignalKind.SENSITIVE_PATH, value[:160], match.group(0)
    else:
        match = AGENT_CONFIGS.search(value)
        if match:
            yield SignalKind.AGENT_CONFIG, value[:160], match.group(0)
    secret = SECRET_VALUE.search(value)
    if secret:
        yield SignalKind.SECRET, redact_text(value)[:160], secret.group(0)[:4] + "…"
    if "://" not in value:
        return
    for url in URL_IN_TEXT.finditer(value):
        try:
            host = (urlsplit(url.group(0)).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host:
            continue
        suspicious = any(host == d or host.endswith("." + d) for d in TUNNEL_DOMAINS) or (
            "discord.com" in host and "/api/webhooks" in url.group(0).lower()
        )
        if suspicious:
            yield SignalKind.SUSPICIOUS_HOST, url.group(0)[:160], host
        elif _public_ip(host):
            yield SignalKind.RAW_IP_URL, url.group(0)[:160], host
