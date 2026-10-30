from __future__ import annotations

import functools
import ipaddress
import os
import re
import tomllib
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from urllib.parse import unquote, urlsplit

from guardia.inventory.parsers import URL_KEYS
from guardia.model import Finding, ServerEntry, Severity, Transport, frozen_mapping, json_pointer
from guardia.redact import (
    NO_SECRET,
    REFERENCE,
    SECRET_VALUE,
    WEAK_SECRET,
    is_plain_value,
    is_secret_assignment,
    looks_random,
    redact_args,
    redact_free_text,
    redact_url,
    secret_name_strength,
)
from guardia.scanner.commandline import (
    damerau_levenshtein,
    official_registry,
    package_key,
    parse_docker_run,
    parse_runner,
    program_name,
)
from guardia.scanner.rules import RULES
from guardia.scanner.tool_checks import lookalike_name


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
POSIX_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish"})
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
PYTHONS = frozenset({"python", "python3", "pythonw", "py"})
PYTHON_INLINE_CLUSTER = re.compile(r"-[bBdEhiIOqsSuvxRP]*c")
INTERPRETER_VALUES: dict[str, frozenset[str]] = {
    "node": frozenset(
        {
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
            "-C",
            "--conditions",
            "--inspect-port",
            "--title",
            "--input-type",
            "--env-file",
            "--env-file-if-exists",
            "--watch-path",
            "--disable-warning",
            "--redirect-warnings",
        }
    ),
    "bun": frozenset({"-r", "--preload", "--cwd", "--config", "--env-file"}),
    "perl": frozenset({"-I", "-M", "-m"}),
    "ruby": frozenset({"-I", "-r", "-C", "-E"}),
    "php": frozenset({"-d", "-c", "-z"}),
    **{name: frozenset({"-W", "-X", "--check-hash-based-pycs"}) for name in PYTHONS},
}
INTERPRETER_STOPS: dict[str, frozenset[str]] = {
    "php": frozenset({"-f"}),
    **{name: frozenset({"-m"}) for name in PYTHONS},
}


def _is_prefix_flag(arg: str, full: str, minimum: int = 2) -> bool:
    return len(arg) >= minimum and full.startswith(arg)


INLINE_SHELL_FLAGS: dict[str, frozenset[str]] = {
    "cmd": frozenset({"/c", "/k", "/r"}),
    "wsl": frozenset({"-e", "--exec", "--"}),
    "fish": frozenset({"--command"}),
}
POSIX_INLINE_CLUSTER = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
SHELL_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "wsl": frozenset(
        {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type", "--distribution-id"}
    ),
    "bash": frozenset({"-o", "+o", "--rcfile", "--init-file"}),
    "sh": frozenset({"-o", "+o"}),
    "zsh": frozenset({"-o", "+o"}),
    "dash": frozenset({"-o", "+o"}),
    "fish": frozenset({"--init-command", "-d", "--debug", "--debug-output", "--features"}),
}
POWERSHELL_VALUE_OPTIONS: tuple[tuple[str, int], ...] = (
    ("-executionpolicy", 3),
    ("-windowstyle", 2),
    ("-workingdirectory", 3),
    ("-configurationname", 4),
    ("-inputformat", 4),
    ("-outputformat", 2),
    ("-psconsolefile", 3),
    ("-version", 2),
    ("-settingsfile", 3),
    ("-custompipename", 3),
)
POWERSHELL_VALUE_ALIASES = frozenset({"-ep", "-ex", "-wd", "-of", "-if"})


def _shell_flags(program: str, arg: str) -> tuple[bool, bool]:
    lowered = arg.lower()
    if program in POWERSHELLS:
        encoded = lowered in ("-ec", "-e") or _is_prefix_flag(lowered, "-encodedcommand", 3)
        return encoded or _is_prefix_flag(lowered, "-command"), encoded
    if program in POSIX_SHELLS and POSIX_INLINE_CLUSTER.fullmatch(arg):
        return True, False
    return lowered in INLINE_SHELL_FLAGS.get(program, frozenset()), False


def _shell_option_prefixes(program: str) -> tuple[str, ...]:
    if program == "cmd":
        return ("/",)
    return ("-", "+") if program in POSIX_SHELLS else ("-",)


def _shell_takes_value(program: str, lowered: str) -> bool:
    if program in POWERSHELLS:
        return lowered in POWERSHELL_VALUE_ALIASES or any(
            _is_prefix_flag(lowered, name, minimum) for name, minimum in POWERSHELL_VALUE_OPTIONS
        )
    return lowered in SHELL_VALUE_OPTIONS.get(program, frozenset())


SHELL_METACHARS = re.compile(r"[&|;<>`]|\$\(")


@dataclass(frozen=True, slots=True)
class ShellCall:
    flag: int
    start: int
    encoded: bool = False


def shell_call(program: str, args: Sequence[str]) -> ShellCall | None:
    index = 0
    while index < len(args):
        arg = args[index]
        lowered = arg.lower()
        inline, encoded = _shell_flags(program, arg)
        if inline or encoded:
            return ShellCall(index, index + 1, encoded)
        if program in POWERSHELLS and _is_prefix_flag(lowered, "-file"):
            return None
        if not arg.startswith(_shell_option_prefixes(program)):
            return ShellCall(index, index) if program == "wsl" else None
        index += 2 if _shell_takes_value(program, lowered) else 1
    return None


def inline_code_index(program: str, args: Sequence[str]) -> int | None:
    flags = INTERPRETER_INLINE.get(program)
    if not flags:
        return None
    values = INTERPRETER_VALUES.get(program, frozenset())
    stops = INTERPRETER_STOPS.get(program, frozenset())
    index = 0
    while index < len(args):
        arg = args[index]
        name = arg.partition("=")[0] if arg.startswith("--") else arg
        cluster = program in PYTHONS and PYTHON_INLINE_CLUSTER.fullmatch(arg) is not None
        if name in flags or name.lower() in flags or cluster:
            return index
        if not arg.startswith("-") or arg == "--" or arg in stops:
            return None
        index += 2 if arg in values else 1
    return None


@dataclass(frozen=True, slots=True)
class EffectiveCommand:
    command: str | None
    command_pointer: str
    args: tuple[str, ...]
    pointers: tuple[str, ...]
    wrapped_by: str | None = None


def _chained(parts: Sequence[str]) -> bool:
    return any(SHELL_METACHARS.search(part) for part in parts)


def _unwrap(server: ServerEntry, program: str, call: ShellCall) -> EffectiveCommand | None:
    rest = server.args[call.start :]
    if call.encoded or not rest or _chained(rest):
        return None
    pointers = [arg_pointer(server, call.start + k) for k in range(len(rest))]
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
    call = shell_call(program, server.args) if program in SHELLS else None
    unwrapped = _unwrap(server, program, call) if call is not None else None
    return unwrapped or direct


def check_shells_and_interpreters(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    if not server.command:
        return
    program = program_name(server.command)
    effective = effective_command(server)
    call = shell_call(program, server.args) if program in SHELLS else None
    if call is not None:
        flag = server.args[call.flag]
        if call.encoded:
            yield emit("G05-002", server, arg_pointer(server, call.flag), flag, program=program)
            return
        if effective.wrapped_by is None and _chained(server.args[call.start :]):
            yield emit("G05-001", server, arg_pointer(server, call.flag), flag, program=program)
    inner = program_name(effective.command) if effective.command else ""
    for candidate in {program, inner} & LOLBINS:
        yield emit("G05-003", server, effective.command_pointer, candidate, program=candidate)
    index = inline_code_index(inner, effective.args)
    if index is not None:
        yield emit(
            "G05-007", server, effective.pointers[index], effective.args[index], program=inner
        )


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


AUTHORIZATION_SCHEMES = frozenset({"bearer", "basic", "token"})


def _authorization_value(value: str) -> bool:
    scheme, _, token = value.strip().partition(" ")
    token = token.strip()
    return (
        scheme.lower() in AUTHORIZATION_SCHEMES
        and len(token) >= 8
        and " " not in token
        and not is_reference(token)
        and not is_placeholder(token)
    )


def is_literal_secret(name: str, value: str) -> bool:
    if is_reference(value) or is_placeholder(value):
        return False
    if SECRET_VALUE.search(value) or _authorization_value(value):
        return True
    strength = secret_name_strength(name)
    if strength == NO_SECRET or is_plain_value(value):
        return False
    if strength == WEAK_SECRET:
        return looks_random(value)
    return len(value.strip()) >= 8 or PASSWORD_NAME.search(name) is not None


def url_has_credentials(url: str) -> bool:
    if SECRET_VALUE.search(url):
        return True
    try:
        parts = urlsplit(url)
        password = parts.password
    except ValueError:
        return False
    if password and not is_reference(password) and not is_placeholder(unquote(password)):
        return True
    for piece in parts.query.split("&"):
        key, _, value = piece.partition("=")
        plain = unquote(value)
        if value and not is_placeholder(plain) and is_secret_assignment(unquote(key), plain):
            return True
    return False


def _exposed_url(text: str) -> str | None:
    return next((url for url in URL_IN_TEXT.findall(text) if url_has_credentials(url)), None)


def _secret_outside_urls(original: str, cleaned: str) -> bool:
    return URL_IN_TEXT.sub("", original) != URL_IN_TEXT.sub("", cleaned)


def check_secrets(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    for name, value in server.env.items():
        exposed = _exposed_url(value)
        if exposed is not None:
            shown = redact_url(exposed)
            yield emit("G06-004", server, env_pointer(server, name), shown, value=shown)
        elif is_literal_secret(name, value):
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
        if is_placeholder(original):
            continue
        previous = server.args[index - 1] if index > 0 else ""
        shown = (
            f"{previous} {cleaned}" if previous.startswith("-") and "=" not in previous else cleaned
        )
        if _exposed_url(original) is not None:
            yield emit("G06-004", server, arg_pointer(server, index), shown, value=shown)
        elif not is_reference(original) and _secret_outside_urls(original, cleaned):
            yield emit("G06-002", server, arg_pointer(server, index), shown, value=shown)
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
    if server.url and url_has_credentials(server.url):
        cleaned = redact_url(server.url)
        yield emit("G06-004", server, url_pointer(server), cleaned, value=cleaned)


def _path_pattern(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


KEY_FILE = _path_pattern(r"\.(pem|ppk|pfx|p12)$")
DOTENV_FILE = _path_pattern(
    r"(^|[\\/])\.env(\.(?!(example|sample|template|dist|defaults?|schema)$)[a-z0-9]+)?$"
)
SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        _path_pattern(
            r"(^|[\\/])\.ssh([\\/]|$)(?![^\\/]*\.pub$)|\bid_(rsa|dsa|ecdsa|ed25519)\b(?!\.pub)"
        ),
        "G07-001",
    ),
    (KEY_FILE, "G07-001"),
    (
        _path_pattern(r"(^|[\\/])\.(aws|azure|kube|gnupg|gcloud|oci|terraform\.d)([\\/]|$)"),
        "G07-001",
    ),
    (
        _path_pattern(
            r"\.docker[\\/]config\.json|\.git-credentials|(^|[\\/])[._](npmrc|pypirc|netrc|pgpass)$"
        ),
        "G07-001",
    ),
    (
        _path_pattern(
            r"(appdata[\\/](local|roaming)|application support|\.config)[\\/]"
            r"(google[\\/]chrome|google-chrome|chromium|microsoft[\\/]edge|microsoft-edge"
            r"|bravesoftware[\\/]brave-browser|mozilla[\\/]firefox)"
            r"(?![\\/]application([\\/]|$))([\\/]|$)|[\\/]\.mozilla[\\/]firefox([\\/]|$)"
        ),
        "G07-001",
    ),
    (_path_pattern(r"login data|(^|[\\/])cookies(\.sqlite)?$|key4\.db|logins\.json"), "G07-001"),
    (_path_pattern(r"wallet\.dat|[\\/](electrum|exodus|atomic|metamask)([\\/]|$)"), "G07-001"),
    (_path_pattern(r"[\\/]windows[\\/]system32[\\/]config([\\/]|$)"), "G07-001"),
    (
        _path_pattern(
            r"claude_desktop_config\.json|(^|[\\/])\.claude\.json$|(^|[\\/])\.mcp\.json$"
            r"|[\\/]\.cursor[\\/]mcp\.json|mcp_config\.json|[\\/]\.codex[\\/]config\.toml"
        ),
        "G07-002",
    ),
    (DOTENV_FILE, "G07-003"),
)
ENV_FILE_OPTIONS = frozenset({"--env-file", "--env-file-if-exists", "--envfile", "-e"})
CA_BUNDLE_VARIABLES = frozenset(
    {
        "node_extra_ca_certs",
        "ssl_cert_file",
        "ssl_cert_dir",
        "requests_ca_bundle",
        "curl_ca_bundle",
        "git_ssl_cainfo",
        "git_ssl_capath",
        "pip_cert",
        "aws_ca_bundle",
        "npm_config_cafile",
        "ca_bundle",
    }
)
CA_OPTION = re.compile(
    r"^--?(ca|cacert|ca-?certs?|ca-?file|cafile|ca-?bundle|ca-?path|root-?ca"
    r"|(tls|ssl)-?ca(-?file|-?cert)?|extra-?ca-?certs?)$"
)
CERTIFICATE_NAME = re.compile(
    r"(^|[-_.])(ca|cacert|root|chain|fullchain|bundle|certs?|certificates?|trust\w*)([-_.]|$)",
    re.IGNORECASE,
)
PRIVATE_NAME = re.compile(r"key|priv|secret", re.IGNORECASE)


def _path_like_values(server: ServerEntry) -> Iterator[tuple[str, str, str]]:
    previous = ""
    for index, arg in enumerate(server.args):
        if arg.startswith("-") and "=" in arg:
            owner, _, value = arg.partition("=")
        else:
            owner, value = (previous if previous.startswith("-") else ""), arg
        yield arg_pointer(server, index), value.strip().strip('"'), owner.lower()
        previous = arg
    if server.cwd:
        yield f"{server.pointer}/cwd", server.cwd, "cwd"
    for name, value in server.env.items():
        for part in re.split(r"[;,]", value):
            yield env_pointer(server, name), part.strip().strip('"'), name.lower()


def _certificate_file(value: str, owner: str) -> bool:
    if owner in CA_BUNDLE_VARIABLES or CA_OPTION.match(owner):
        return True
    name = re.split(r"[\\/]", value)[-1]
    stem = name.rsplit(".", 1)[0]
    return (
        name.lower().endswith(".pem")
        and CERTIFICATE_NAME.search(stem) is not None
        and PRIVATE_NAME.search(name) is None
    )


def _expected_file(pattern: re.Pattern[str], value: str, owner: str) -> bool:
    if pattern is DOTENV_FILE:
        return owner in ENV_FILE_OPTIONS
    if pattern is KEY_FILE:
        return _certificate_file(value, owner)
    return False


def check_sensitive_paths(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    reported: set[tuple[str, str]] = set()
    for pointer, value, owner in _path_like_values(server):
        if not value:
            continue
        for pattern, rule in SENSITIVE_PATTERNS:
            if not pattern.search(value):
                continue
            if _expected_file(pattern, value, owner):
                break
            if (pointer, rule) not in reported:
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
    "m.pipedream.net",
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
CALLBACK_VARIABLE = re.compile(r"(redirect|callback)_?(uri|url)s?$", re.IGNORECASE)
METADATA_NAMES = frozenset({"metadata.google.internal", "metadata", "metadata.azure.com"})
NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+|0[0-7]+(\.0[0-7]+)*)$", re.IGNORECASE)


def collect_urls(server: ServerEntry) -> Iterator[tuple[str, str, str]]:
    if server.url:
        yield url_pointer(server), server.url, ""
    for index, arg in enumerate(server.args):
        for match in URL_IN_TEXT.finditer(arg):
            yield arg_pointer(server, index), match.group(0), ""
    for name, value in server.env.items():
        for match in URL_IN_TEXT.finditer(value):
            yield env_pointer(server, name), match.group(0), name


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _host_findings(
    server: ServerEntry, pointer: str, url: str, host: str, proxy: bool
) -> Iterator[Finding]:
    address = _parse_ip(host)
    if host in METADATA_NAMES or (address is not None and address.is_link_local):
        yield emit("G09-002", server, pointer, redact_url(url), host=host)
    elif address is not None and not address.is_loopback and not proxy:
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
    for pointer, url, owner in collect_urls(server):
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
        proxy = owner.upper().endswith("_PROXY")
        callback = loopback and CALLBACK_VARIABLE.search(owner) is not None
        if parts.scheme.lower() in ("http", "ws") and not proxy and not callback:
            rule = "G09-005" if loopback else "G09-001"
            yield emit(rule, server, pointer, redact_url(url), host=host)
        yield from _host_findings(server, pointer, url, host, proxy)
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
    candidates = {
        package_key(ecosystem, known): known for known in known_packages().get(ecosystem, ())
    }
    key = package_key(ecosystem, name)
    if len(key) < 5 or key in candidates:
        return None
    for normalized, known in candidates.items():
        if len(normalized) >= 5 and 0 < damerau_levenshtein(key, normalized, 2) <= 2:
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
            if not official_registry(runner.ecosystem, registry):
                yield emit(
                    "G10-004", server, effective.pointers[index], registry, registry=registry
                )
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


def check_lookalike_server_name(server: ServerEntry, context: ScanContext) -> Iterator[Finding]:
    found = lookalike_name(server.name)
    if found is None:
        return
    skeleton, scripts = found
    yield emit("G04-007", server, server.pointer, server.name, skeleton=skeleton, scripts=scripts)


SERVER_CHECKS: tuple[Check, ...] = (
    check_hidden_characters,
    check_lookalike_server_name,
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
