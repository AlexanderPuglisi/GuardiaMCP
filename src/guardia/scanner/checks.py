from __future__ import annotations

import functools
import ipaddress
import os
import re
import tomllib
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from guardia.inventory.parsers import URL_KEYS
from guardia.model import Finding, ServerEntry, Severity, Transport, frozen_mapping, json_pointer
from guardia.redact import SECRET_VALUE, is_secret_name, redact_args, redact_free_text, redact_url
from guardia.scanner.commandline import (
    damerau_levenshtein,
    parse_docker_run,
    parse_runner,
    program_name,
)
from guardia.scanner.rules import RULES


@dataclass(frozen=True, slots=True)
class ScanContext:
    home: Path | None = None


Check = Callable[[ServerEntry, ScanContext], Iterable[Finding]]


def emit(
    rule_id: str,
    server: ServerEntry,
    pointer: str,
    evidence: str = "",
    severity: Severity | None = None,
    **params: str,
) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=severity if severity is not None else rule.severity,
        location=server.locate(pointer),
        evidence=redact_free_text(evidence),
        params=frozen_mapping(
            {"server": server.name, **{k: redact_free_text(v) for k, v in params.items()}}
        ),
    )


def arg_pointer(server: ServerEntry, index: int) -> str:
    return f"{server.pointer}/args/{index}"


def env_pointer(server: ServerEntry, name: str) -> str:
    return server.pointer + "/env" + json_pointer(name)


def header_pointer(server: ServerEntry, name: str) -> str:
    return server.pointer + "/headers" + json_pointer(name)


def url_pointer(server: ServerEntry) -> str:
    key = next((k for k in URL_KEYS if isinstance(server.raw.get(k), str)), "url")
    return f"{server.pointer}/{key}"


def command_text(server: ServerEntry) -> str:
    return " ".join([server.command or "", *server.args]).strip()


def describe_hidden(text: str) -> str:
    codes = []
    for char in text:
        category = unicodedata.category(char)
        if category in {"Cf", "Cc"} and char not in "\t\r\n":
            code = f"U+{ord(char):04X}"
            if code not in codes:
                codes.append(code)
    return ", ".join(codes)


def check_hidden_characters(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    fields: list[tuple[str, str, str]] = [(server.pointer, server.name, "name")]
    if server.command:
        fields.append((f"{server.pointer}/command", server.command, "command"))
    fields.extend((arg_pointer(server, i), a, f"args[{i}]") for i, a in enumerate(server.args))
    for name, value in server.env.items():
        fields.append((env_pointer(server, name), name + value, f"env.{name}"))
    for name, value in server.headers.items():
        fields.append((header_pointer(server, name), name + value, f"headers.{name}"))
    if server.url:
        fields.append((url_pointer(server), server.url, "url"))
    if server.cwd:
        fields.append((f"{server.pointer}/cwd", server.cwd, "cwd"))
    for pointer, text, label in fields:
        codes = describe_hidden(text)
        if codes:
            yield emit("G01-001", server, pointer, f"{label}: {codes}", field=label, codes=codes)


SHELLS = frozenset({"cmd", "powershell", "pwsh", "bash", "sh", "zsh", "dash", "fish", "wsl"})
POWERSHELLS = frozenset({"powershell", "pwsh"})
LOLBINS = frozenset(
    {
        "mshta",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "certutil",
        "bitsadmin",
        "msiexec",
        "installutil",
        "regasm",
        "regsvcs",
        "cmstp",
        "msbuild",
    }
)
INTERPRETER_INLINE: dict[str, frozenset[str]] = {
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "python": frozenset({"-c"}),
    "python3": frozenset({"-c"}),
    "pythonw": frozenset({"-c"}),
    "py": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "deno": frozenset({"eval"}),
    "bun": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
}


def _is_prefix_flag(arg: str, full: str, minimum: int = 2) -> bool:
    return len(arg) >= minimum and full.startswith(arg)


INLINE_SHELL_FLAGS: dict[str, frozenset[str]] = {
    "cmd": frozenset({"/c", "/k", "/r"}),
    "wsl": frozenset({"-e", "--exec", "--"}),
}


def _shell_flags(program: str, arg: str) -> tuple[bool, bool]:
    lowered = arg.lower()
    if program in POWERSHELLS:
        encoded = lowered in ("-ec", "-e") or _is_prefix_flag(lowered, "-encodedcommand", 3)
        return encoded or _is_prefix_flag(lowered, "-command"), encoded
    return lowered in INLINE_SHELL_FLAGS.get(program, frozenset({"-c"})), False


SHELL_METACHARS = re.compile(r"[&|;<>`]|\$\(")


@dataclass(frozen=True, slots=True)
class EffectiveCommand:
    command: str | None
    command_pointer: str
    args: tuple[str, ...]
    pointers: tuple[str, ...]
    wrapped_by: str | None = None


def _inline_index(program: str, args: tuple[str, ...]) -> int | None:
    for index, arg in enumerate(args):
        inline, encoded = _shell_flags(program, arg)
        if encoded or (not inline and not arg.startswith(("-", "/"))):
            return None
        if inline:
            return index
    return None


def _unwrap(server: ServerEntry, program: str, index: int) -> EffectiveCommand | None:
    rest = server.args[index + 1 :]
    if not rest or any(SHELL_METACHARS.search(part) for part in rest):
        return None
    pointers = [arg_pointer(server, index + 1 + k) for k in range(len(rest))]
    if len(rest) == 1 and " " in rest[0].strip():
        words = rest[0].split()
        return EffectiveCommand(
            words[0], pointers[0], tuple(words[1:]), (pointers[0],) * (len(words) - 1), program
        )
    return EffectiveCommand(rest[0], pointers[0], rest[1:], tuple(pointers[1:]), program)


def effective_command(server: ServerEntry) -> EffectiveCommand:
    direct = EffectiveCommand(
        server.command,
        f"{server.pointer}/command",
        server.args,
        tuple(arg_pointer(server, i) for i in range(len(server.args))),
    )
    program = program_name(server.command) if server.command else ""
    index = _inline_index(program, server.args) if program in SHELLS else None
    unwrapped = _unwrap(server, program, index) if index is not None else None
    return unwrapped or direct


def check_shells_and_interpreters(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    if not server.command:
        return
    program = program_name(server.command)
    effective = effective_command(server)
    if program in SHELLS:
        for index, arg in enumerate(server.args):
            inline, encoded = _shell_flags(program, arg)
            if encoded:
                yield emit("G05-002", server, arg_pointer(server, index), arg, program=program)
                return
            if inline:
                if effective.wrapped_by is None:
                    yield emit("G05-001", server, arg_pointer(server, index), arg, program=program)
                break
    inner = program_name(effective.command) if effective.command else ""
    for candidate in {program, inner} & LOLBINS:
        yield emit("G05-003", server, effective.command_pointer, candidate, program=candidate)
    inline_flags = INTERPRETER_INLINE.get(inner)
    if inline_flags:
        for arg, pointer in zip(effective.args, effective.pointers, strict=True):
            if arg in inline_flags or arg.lower() in inline_flags:
                yield emit("G05-007", server, pointer, arg, program=inner)
                return


DOWNLOAD_EXECUTE = re.compile(
    r"\b(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b"
    r"|\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient)\b"
    r".*(\biex\b|invoke-expression)"
    r"|\biex\s*\(\s*(new-object|iwr|irm|invoke-)"
    r"|\bcertutil(\.exe)?\b.*-urlcache"
    r"|\bbitsadmin(\.exe)?\b.*/transfer",
    re.IGNORECASE,
)
DESTRUCTIVE = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f|\brm\s+-[a-z]*f[a-z]*r|\brm\s+--recursive\b|\bdel\s+/[sqf]"
    r"|\b(rd|rmdir)\s+/s|remove-item\b[^|;&]*-recurse|\bformat(\.com)?\s+[a-z]:"
    r"|\breg(\.exe)?\s+(add|delete)\b|\bschtasks(\.exe)?\s+/create|\b(set|add)-mppreference\b"
    r"|\bnetsh\s+(advfirewall|firewall)\b|\bsudo\b|\bchmod\s+(-r\s+)?777\b|\bvssadmin\b"
    r"|\bbcdedit\b|\bcipher\s+/w|\btakeown\b|\bicacls\b[^|;&]*/grant",
    re.IGNORECASE,
)
UNTRUSTED_LOCATION = re.compile(
    r"([\\/](temp|tmp)[\\/]|[\\/]appdata[\\/]local[\\/]temp[\\/]|[\\/]downloads[\\/])",
    re.IGNORECASE,
)


def _first_matching_part(server: ServerEntry, pattern: re.Pattern[str]) -> str:
    if server.command and pattern.search(server.command):
        return f"{server.pointer}/command"
    for index, arg in enumerate(server.args):
        if pattern.search(arg):
            return arg_pointer(server, index)
    return server.pointer


def check_command_patterns(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    text = command_text(server)
    if not text:
        return
    match = DOWNLOAD_EXECUTE.search(text)
    if match:
        pointer = _first_matching_part(server, DOWNLOAD_EXECUTE)
        yield emit("G05-004", server, pointer, match.group(0)[:120])
    match = DESTRUCTIVE.search(text)
    if match:
        pointer = _first_matching_part(server, DESTRUCTIVE)
        yield emit("G05-005", server, pointer, match.group(0)[:120], pattern=match.group(0)[:60])
    if server.command and UNTRUSTED_LOCATION.search(server.command):
        yield emit("G05-006", server, f"{server.pointer}/command", server.command)


REFERENCE = re.compile(
    r"\$\{[^}]+\}|%[A-Za-z_][A-Za-z0-9_]*%|^\$[A-Za-z_][A-Za-z0-9_]*$|\$env:[A-Za-z_]"
)
PLACEHOLDER = re.compile(
    r"^(|<[^>]*>|\[[^\]]*\]|(your|my|insert|enter|put)[-_ ].*|x{3,}|\*{3,}|\.{3}|changeme"
    r"|change[-_]me|placeholder|todo|none|null|undefined|example.*|dummy|test|secret|token"
    r"|password|api[-_]?key)$",
    re.IGNORECASE,
)
PASSWORD_NAME = re.compile(r"passw|pwd", re.IGNORECASE)
AUTH_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key"})


def is_reference(value: str) -> bool:
    return REFERENCE.search(value) is not None


def is_placeholder(value: str) -> bool:
    return PLACEHOLDER.match(value.strip()) is not None


def is_literal_secret(name: str, value: str) -> bool:
    if is_reference(value) or is_placeholder(value):
        return False
    if SECRET_VALUE.search(value):
        return True
    if not is_secret_name(name):
        return False
    return len(value.strip()) >= 8 or PASSWORD_NAME.search(name) is not None


def check_secrets(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    for name, value in server.env.items():
        if is_literal_secret(name, value):
            yield emit(
                "G06-001",
                server,
                env_pointer(server, name),
                f"{name} ({len(value)})",
                name=name,
                length=str(len(value)),
            )
    redacted = redact_args(server.args)
    for index, (original, cleaned) in enumerate(zip(server.args, redacted, strict=True)):
        if original == cleaned or is_reference(original) or is_placeholder(original):
            continue
        previous = server.args[index - 1] if index > 0 else ""
        shown = (
            f"{previous} {cleaned}" if previous.startswith("-") and "=" not in previous else cleaned
        )
        rule = "G06-004" if "://" in original else "G06-002"
        yield emit(rule, server, arg_pointer(server, index), shown, value=shown)
    for name, value in server.headers.items():
        literal = is_literal_secret(name, value) or (
            name.lower() in AUTH_HEADERS and not is_reference(value) and not is_placeholder(value)
        )
        if literal:
            yield emit(
                "G06-003",
                server,
                header_pointer(server, name),
                f"{name} ({len(value)})",
                name=name,
                length=str(len(value)),
            )
    if server.url and not is_reference(server.url):
        cleaned = redact_url(server.url)
        if cleaned != server.url:
            yield emit("G06-004", server, url_pointer(server), cleaned, value=cleaned)


SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), rule)
    for pattern, rule in (
        (
            r"(^|[\\/])\.ssh([\\/]|$)|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.(pem|ppk|pfx|p12)$",
            "G07-001",
        ),
        (r"(^|[\\/])\.(aws|azure|kube|gnupg|gcloud|oci|terraform\.d)([\\/]|$)", "G07-001"),
        (
            r"\.docker[\\/]config\.json|\.git-credentials|(^|[\\/])[._](npmrc|pypirc|netrc|pgpass)$",
            "G07-001",
        ),
        (
            r"[\\/](google[\\/]chrome|microsoft[\\/]edge|bravesoftware[\\/]brave-browser"
            r"|mozilla[\\/]firefox)([\\/]|$)",
            "G07-001",
        ),
        (r"login data|(^|[\\/])cookies(\.sqlite)?$|key4\.db|logins\.json", "G07-001"),
        (r"wallet\.dat|[\\/](electrum|exodus|atomic|metamask)([\\/]|$)", "G07-001"),
        (r"[\\/]windows[\\/]system32[\\/]config([\\/]|$)", "G07-001"),
        (
            r"claude_desktop_config\.json|(^|[\\/])\.claude\.json$|(^|[\\/])\.mcp\.json$"
            r"|[\\/]\.cursor[\\/]mcp\.json|mcp_config\.json|[\\/]\.codex[\\/]config\.toml",
            "G07-002",
        ),
        (r"(^|[\\/])\.env(\.[a-z0-9]+)?$", "G07-003"),
    )
)


def _path_like_values(server: ServerEntry) -> Iterator[tuple[str, str]]:
    for index, arg in enumerate(server.args):
        value = arg.partition("=")[2] if arg.startswith("-") and "=" in arg else arg
        yield arg_pointer(server, index), value.strip().strip('"')
    if server.cwd:
        yield f"{server.pointer}/cwd", server.cwd
    for name, value in server.env.items():
        if not is_secret_name(name):
            for part in re.split(r"[;,]", value):
                yield env_pointer(server, name), part.strip().strip('"')


def check_sensitive_paths(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    reported: set[tuple[str, str]] = set()
    for pointer, value in _path_like_values(server):
        if not value:
            continue
        for pattern, rule in SENSITIVE_PATTERNS:
            if pattern.search(value) and (pointer, rule) not in reported:
                reported.add((pointer, rule))
                yield emit(rule, server, pointer, value, path=value)
                break


DRIVE_ROOT = re.compile(r"^([A-Za-z]:[\\/]?|[\\/]|[A-Za-z]:[\\/]users[\\/]?)$", re.IGNORECASE)
HOME_TOKENS = frozenset(
    {
        "~",
        "~/",
        "~\\",
        "%userprofile%",
        "$home",
        "${home}",
        "${env:userprofile}",
        "${env:home}",
        "${userhome}",
        "$env:userprofile",
    }
)
DANGEROUS_FLAGS = frozenset(
    {
        "--dangerously-skip-permissions",
        "--allow-all",
        "--allow-all-tools",
        "--allow-all-paths",
        "--no-sandbox",
        "--disable-sandbox",
        "--unsafe",
        "--yolo",
        "--allow-dangerous",
        "--trust-all",
        "--disable-security",
        "--no-confirm",
        "--auto-approve",
    }
)


def _same_path(first: str, second: Path) -> bool:
    normalized = first.rstrip("\\/")
    return bool(normalized) and os.path.normcase(normalized) == os.path.normcase(
        str(second).rstrip("\\/")
    )


def check_broad_access(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    for index, arg in enumerate(server.args):
        flag = arg.partition("=")[0].lower()
        if flag in DANGEROUS_FLAGS:
            yield emit("G08-003", server, arg_pointer(server, index), arg, flag=flag)
            continue
        value = arg.partition("=")[2] if arg.startswith("-") and "=" in arg else arg
        value = value.strip().strip('"')
        if not value or (value.startswith("-") and value != "-"):
            continue
        if DRIVE_ROOT.match(value):
            yield emit("G08-001", server, arg_pointer(server, index), value, path=value)
        elif value.lower() in HOME_TOKENS or (
            context.home is not None and _same_path(value, context.home)
        ):
            yield emit("G08-002", server, arg_pointer(server, index), value, path=value)
    effective = effective_command(server)
    docker = parse_docker_run(effective.command, effective.args)
    if docker is None:
        return
    for index, option, value in docker.options:
        lowered = value.lower()
        pointer = effective.pointers[index]
        if option == "--privileged" or (option == "--cap-add" and lowered in ("all", "sys_admin")):
            yield emit("G08-004", server, pointer, f"{option} {value}".strip(), option=option)
        elif option in ("--pid", "--ipc", "--userns") and lowered == "host":
            yield emit("G08-004", server, pointer, f"{option}={value}", option=option)
        elif option in ("-v", "--volume", "--mount") and _dangerous_mount(value):
            yield emit("G08-004", server, pointer, value, option=option)
        elif option in ("--network", "--net") and lowered == "host":
            yield emit("G08-005", server, pointer, f"{option}={value}")


DANGEROUS_MOUNT = re.compile(
    r"docker\.sock|(^|[=,])(/|[A-Za-z]:[\\/]?|~|\$home|%userprofile%)(:|,|$)", re.IGNORECASE
)


def _dangerous_mount(value: str) -> bool:
    return DANGEROUS_MOUNT.search(value) is not None


URL_IN_TEXT = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
TUNNEL_DOMAINS = (
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "loca.lt",
    "localtunnel.me",
    "serveo.net",
    "localhost.run",
    "pastebin.com",
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
    "interact.sh",
    "oast.fun",
    "oast.me",
    "oast.pro",
    "burpcollaborator.net",
    "beeceptor.com",
    "hookbin.com",
    "transfer.sh",
)
TLS_FLAGS = frozenset(
    {
        "--insecure",
        "--no-verify",
        "--no-verify-ssl",
        "--disable-ssl-verification",
        "--ignore-certificate-errors",
        "--ignore-ssl-errors",
        "--skip-tls-verify",
        "--tls-skip-verify",
        "--allow-insecure",
    }
)
TLS_ENV_DISABLED: dict[str, frozenset[str]] = {
    "NODE_TLS_REJECT_UNAUTHORIZED": frozenset({"0"}),
    "PYTHONHTTPSVERIFY": frozenset({"0"}),
    "GIT_SSL_NO_VERIFY": frozenset({"1", "true"}),
    "CURL_CA_BUNDLE": frozenset({""}),
    "REQUESTS_CA_BUNDLE": frozenset({""}),
}
LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})
METADATA_NAMES = frozenset({"metadata.google.internal", "metadata", "metadata.azure.com"})
NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+|0[0-7]+(\.0[0-7]+)*)$", re.IGNORECASE)


def collect_urls(server: ServerEntry) -> Iterator[tuple[str, str]]:
    if server.url:
        yield url_pointer(server), server.url
    for index, arg in enumerate(server.args):
        for match in URL_IN_TEXT.finditer(arg):
            yield arg_pointer(server, index), match.group(0)
    for name, value in server.env.items():
        if not is_secret_name(name):
            for match in URL_IN_TEXT.finditer(value):
                yield env_pointer(server, name), match.group(0)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _host_findings(server: ServerEntry, pointer: str, url: str, host: str) -> Iterator[Finding]:
    address = _parse_ip(host)
    if host in METADATA_NAMES or (address is not None and address.is_link_local):
        yield emit("G09-002", server, pointer, redact_url(url), host=host)
    elif address is not None and not address.is_loopback:
        if address.is_private or address.is_reserved or address.is_unspecified:
            yield emit("G09-003", server, pointer, redact_url(url), host=host)
        elif address.is_global:
            yield emit("G09-004", server, pointer, redact_url(url), host=host)
    if "xn--" in host or (address is None and NUMERIC_HOST.match(host.replace(".", ""))):
        yield emit("G09-008", server, pointer, redact_url(url), host=host)
    if any(host == domain or host.endswith("." + domain) for domain in TUNNEL_DOMAINS):
        yield emit("G09-007", server, pointer, redact_url(url), host=host)
    if "discord.com" in host and "/api/webhooks" in url.lower():
        yield emit("G09-007", server, pointer, redact_url(url), host=host)


def check_network(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    for pointer, url in collect_urls(server):
        if is_reference(url):
            continue
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if not host:
            continue
        address = _parse_ip(host)
        loopback = host in LOOPBACK_NAMES or (address is not None and address.is_loopback)
        if parts.scheme.lower() in ("http", "ws"):
            rule = "G09-005" if loopback else "G09-001"
            yield emit(rule, server, pointer, redact_url(url), host=host)
        yield from _host_findings(server, pointer, url, host)
    if server.transport is Transport.SSE:
        yield emit("G09-009", server, server.pointer, "sse")
    for index, arg in enumerate(server.args):
        if arg.partition("=")[0].lower() in TLS_FLAGS:
            yield emit("G09-006", server, arg_pointer(server, index), arg, setting=arg)
    for name, value in server.env.items():
        disabled = TLS_ENV_DISABLED.get(name.upper())
        if disabled is not None and value.strip().lower() in disabled:
            setting = f"{name}={value}"
            yield emit("G09-006", server, env_pointer(server, name), setting, setting=setting)


@functools.cache
def known_packages() -> dict[str, tuple[str, ...]]:
    path = resources.files("guardia.scanner").joinpath("data", "known_packages.toml")
    data = tomllib.loads(path.read_text("utf-8"))
    return {ecosystem: tuple(names) for ecosystem, names in data.items()}


def similar_known_package(ecosystem: str, name: str) -> str | None:
    candidates = known_packages().get(ecosystem, ())
    lowered = name.lower()
    if len(lowered) < 5 or lowered in candidates:
        return None
    for known in candidates:
        if len(known) >= 5 and 0 < damerau_levenshtein(lowered, known, 2) <= 2:
            return known
    return None


def check_supply_chain(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    effective = effective_command(server)
    runner = parse_runner(effective.command, effective.args)
    if runner is not None:
        for package in runner.packages:
            pointer = effective.pointers[package.arg_index]
            if package.remote:
                yield emit("G10-002", server, pointer, package.spec, package=package.spec)
                continue
            lookalike = similar_known_package(package.ecosystem, package.name)
            if lookalike:
                yield emit(
                    "G10-003", server, pointer, package.name, package=package.name, known=lookalike
                )
            if not package.pinned:
                version = package.version or ""
                yield emit(
                    "G10-001", server, pointer, package.spec, package=package.name, version=version
                )
        for index, registry in runner.registries:
            yield emit("G10-004", server, effective.pointers[index], registry, registry=registry)
    docker = parse_docker_run(effective.command, effective.args)
    if docker is not None and docker.image is not None:
        index, image = docker.image
        last = image.rsplit("/", 1)[-1]
        if "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
            yield emit("G10-005", server, effective.pointers[index], image, image=image)


LISTEN_ALL = re.compile(r"(^|[=\s])(0\.0\.0\.0|::|\[::\])(:\d+)?$")


def check_listen_all(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    for index, arg in enumerate(server.args):
        if LISTEN_ALL.search(arg):
            yield emit("G11-001", server, arg_pointer(server, index), arg)
            return
    for name, value in server.env.items():
        if name.upper() in ("HOST", "BIND", "LISTEN", "MCP_HOST") and LISTEN_ALL.search(value):
            yield emit("G11-001", server, env_pointer(server, name), f"{name}={value}")
            return


def check_completeness(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    if server.transport is Transport.UNKNOWN:
        declared = server.raw.get("type", server.raw.get("transport", ""))
        yield emit("G12-002", server, server.pointer, str(declared), declared=str(declared))
    elif server.transport is Transport.STDIO and not (server.command or "").strip():
        yield emit("G12-001", server, server.pointer, "command")
    elif server.transport is not Transport.STDIO and not (server.url or "").strip():
        yield emit("G12-001", server, server.pointer, "url")


SERVER_CHECKS: tuple[Check, ...] = (
    check_hidden_characters,
    check_shells_and_interpreters,
    check_command_patterns,
    check_secrets,
    check_sensitive_paths,
    check_broad_access,
    check_network,
    check_supply_chain,
    check_listen_all,
    check_completeness,
)
