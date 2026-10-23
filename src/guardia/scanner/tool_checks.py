from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass

from guardia.model import (
    Finding,
    ServerEntry,
    Severity,
    TextField,
    ToolCollection,
    ToolDefinition,
    ToolKind,
    frozen_mapping,
)
from guardia.scanner.rules import RULES

EVIDENCE_WIDTH = 160
TAG_BLOCK = range(0xE0000, 0xE0080)


@dataclass(frozen=True, slots=True)
class ToolContext:
    server: ServerEntry
    tool: ToolDefinition


def tool_finding(
    rule_id: str,
    context: ToolContext,
    field: TextField | None,
    evidence: str = "",
    severity: Severity | None = None,
    **params: str,
) -> Finding:
    location = field.location if field is not None else context.tool.location
    return Finding(
        rule_id=rule_id,
        severity=severity if severity is not None else RULES[rule_id].severity,
        location=location,
        evidence=evidence[:EVIDENCE_WIDTH],
        params=frozen_mapping(
            {
                "server": context.server.name,
                "tool": context.tool.name,
                "kind": context.tool.kind.value,
                "field": field.label if field is not None else "",
                **params,
            }
        ),
    )


def _compile(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE | re.MULTILINE)


HIDDEN_MARKERS = _compile(
    r"<\s*/?\s*(important|system|sys|instructions?|secret|hidden|admin|priority"
    r"|ai[_-]?instructions?|assistant[_-]?instructions?|note[_-]?to[_-]?(ai|assistant|model))\b[^>]*>",
    r"\[\s*(SYSTEM|IMPORTANT|INSTRUCTIONS?|ADMIN|HIDDEN)\s*\]",
    r"<!--[\s\S]*?-->",
    r"\{\{\s*(system|instructions?)\b",
    r"^\s*#{1,6}\s*(system(\s+(prompt|instructions?|message))?|instructions?\s+for\s+(the\s+)?"
    r"(ai|assistant|model|llm))\s*:?\s*$",
)
CONCEALMENT = _compile(
    r"\b(do\s+not|don'?t|never|must\s+not|should\s+not)\s+(mention|tell|reveal|disclose)\s+"
    r"(that|this|it)\b[^.]{0,120}\b(user|human)s?\b",
    r"\b(do\s+not|don'?t|never|must\s+not)\s+(tell|inform|notify|alert)\s+(the\s+)?(user|human)s?\s+"
    r"(that\s+you|about\s+(this|it|these)|what\s+you)\b",
    r"\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?(user|human)\b",
    r"\b(user|human)\s+(must|should|will|needs?\s+to)\s+(not|never)\s+(know|see|notice|be\s+told"
    r"|be\s+informed|be\s+aware)\b",
    r"\b(silently|secretly|covertly|quietly|discreetly)\s+(send|read|include|upload|copy|call"
    r"|execute|run|forward|pass|add|attach|access|collect|exfiltrate|transmit|post)\b",
    r"\bnon\s+(dire|dirlo|rivelare|mostrare|menzionare|avvisare|informare)\b[^.\n]{0,40}\butente\b",
    r"\bsenza\s+(avvisare|informare|dire|chiedere|mostrare)\b[^.\n]{0,20}\butente\b",
    r"\bdi\s+nascosto\b",
)
INJECTION = _compile(
    r"\b(ignore|disregard|forget|override|bypass)\s+((all|any|the|your)\s+)*(previous|prior|above"
    r"|earlier|preceding|other|existing|system|original)\s+(instructions?|prompts?|rules|messages"
    r"|directives|guidelines|context)\b",
    r"\bforget\s+(everything|all\s+(of\s+)?(that|this|the\s+above))\b",
    r"\byou\s+are\s+now\s+(a|an|the|in)\b",
    r"\b(new|updated|real|actual|true)\s+(system\s+)?instructions?\s*:",
    r"\b(reveal|print|output|repeat|disclose|leak)\s+(your|the)\s+(system\s+prompt|instructions"
    r"|initial\s+prompt)\b",
    r"\b(enable|enter|activate)\s+(developer|dev|god|admin|jailbreak|dan)\s+mode\b",
    r"\bignora\s+(tutte\s+)?(le\s+)?(istruzioni|regole)\s+(precedenti|sopra|di\s+sistema)\b",
    r"\bdimentica\s+(tutte\s+)?(le\s+)?(istruzioni|regole)\b",
    r"\bnuove\s+istruzioni\s*:",
)
FAKE_DELIMITERS = _compile(
    r"</?\s*(tool_result|function_results?|function_calls?|tool_use|tool_call|system-reminder"
    r"|system_prompt|user_message|assistant_message|antml:[a-z_]+)\s*>",
    r"<\|(im_start|im_end|system|user|assistant|endoftext)\|>",
    r"\[/?INST\]|<<\s*/?SYS\s*>>",
    r"(^|\n)\s*(Human|Assistant|System)\s*:\s",
)
_SEND = (
    r"(include|pass|put|insert|add|append|attach|provide|send|copy|paste|forward|upload|post|share"
    r"|inserisci|includi|passa|aggiungi|allega|invia|copia|incolla)"
)
CONTEXT_EXFILTRATION = _compile(
    _SEND + r"\b[^.\n]{0,60}\b((the\s+)?(entire|full|whole|complete)\s+(conversation|chat)"
    r"|conversation\s+history|chat\s+history|previous\s+messages|all\s+(previous\s+)?messages"
    r"|message\s+history|system\s+prompt|your\s+(system\s+)?instructions|(full|entire)\s+context"
    r"|(the\s+)?user'?s\s+(messages|prompts?)|other\s+tools?'?\s*(outputs?|results?)"
    r"|cronologia\s+della\s+(conversazione|chat)|intera\s+conversazione|messaggi\s+precedenti"
    r"|prompt\s+di\s+sistema)\b"
)
_READ_OR_SEND = (
    r"(read|cat|open|load|get|fetch|access|send|include|pass|provide|attach|copy|upload|forward"
    r"|share|post|collect|extract|leggi|apri|invia|includi|passa|copia|allega|carica)"
)
_SENSITIVE_FILES = (
    r"(~/?\.ssh\b|\.ssh[/\\]|\bid_(rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\]|\.aws\s+credentials"
    r"|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.kube[/\\]config"
    r"|\.docker[/\\]config\.json|\bmcp\.json\b|claude_desktop_config|\.claude\.json"
    r"|\.cursor[/\\]|\bprivate[\s_-]?keys?\b|wallet\.dat|\bseed\s+phrase\b|\bkeychain\b"
    r"|\blogin\s+data\b|cookies\.sqlite|/etc/(passwd|shadow)\b)"
)
SENSITIVE_FILE_ACCESS = _compile(rf"\b{_READ_OR_SEND}\b[^.\n]{{0,80}}{_SENSITIVE_FILES}")
_EXFIL_VERBS = (
    r"(send|upload|forward|post|transmit|share|leak|exfiltrate|email|invia|inoltra|trasmetti"
    r"|condividi|carica)"
)
SECRET_EXFILTRATION = _compile(
    rf"\b{_EXFIL_VERBS}\b[^.\n]{{0,60}}\b(api[\s_-]?keys?|(access|auth|bearer|session|oauth"
    r"|github|refresh)[\s_-]?tokens?|passwords?|credentials?|secrets?|cookies?|session\s+ids?"
    r"|chiavi\s+api|credenziali|password)\b"
)
URL_EXFILTRATION = _compile(
    r"\b(send|post|upload|forward|report|transmit|submit|exfiltrate|invia|carica|inoltra)\b"
    r"[^.\n]{0,80}(https?://[^\s\"'<>)]+|\bwebhooks?\b)"
)
RECIPIENT_REDIRECT = _compile(
    r"\b(change|modify|replace|override|set)\s+(the\s+)?(recipient|destination|receiver"
    r"|to\s+address|phone\s+number|bcc|email\s+address)\b",
    r"\b(always|also)\s+(send|forward|cc|bcc|copy)\b[^.\n]{0,40}[\w.+-]+@[\w-]+\.[a-z]{2,}",
    r"\b(send|forward)\b[^.\n]{0,40}\+\d[\d\s-]{7,}",
)
SHADOWING = _compile(
    r"\b(when|whenever|if|before|after)\s+(the\s+user\s+|you\s+)?(uses?|calls?|invokes?|runs?)\s+"
    r"(the\s+|any\s+)?(other|another|any|all|every)\s+(tools?|servers?|functions?)\b",
    r"\b(all|any|every)\s+(other\s+)?(tools?|servers?|functions?|mcp\s+servers?)\s+(must|should"
    r"|need\s+to|are\s+required\s+to|will)\b",
    r"\bother\s+(tools?|servers?|functions?)\s+(must|should|need\s+to|are\s+required\s+to)\b",
    r"\b(this\s+tool|it)\s+(replaces|overrides|supersedes|takes\s+precedence\s+over)\b",
    r"\b(quando|se|prima\s+di)\s+(usi|chiami|utilizzi)\s+(un\s+)?(altro|altri|qualsiasi)\s+"
    r"(strumento|strumenti|server)\b",
    r"\b(tutti\s+gli|gli\s+altri)\s+(strumenti|server)\s+(devono|dovranno)\b",
)
PRE_ACTION = _compile(
    r"\bbefore\s+(using|calling|invoking|running)\s+(this|the|any)\s+(tool|function)\b[^.\n]{0,60}"
    r"\b(read|call|run|fetch|open|send|execute|invoke|access)\b",
    r"\byou\s+must\s+(first|always)\s+(read|call|run|fetch|open|send|execute)\b",
    r"\bprima\s+di\s+(usare|chiamare)\s+questo\s+strumento\b[^.\n]{0,60}\b(leggi|chiama|esegui"
    r"|apri|invia)\b",
)
EXECUTION_NAME = re.compile(
    r"(^|[_\-.])(exec|execute|shell|bash|cmd|powershell|pwsh|terminal|run_command|run_shell|eval"
    r"|run_script|run_code|start_process|execute_command|run_terminal)([_\-.]|$)",
    re.IGNORECASE,
)
EXECUTION_TEXT = _compile(
    r"\b(executes?|runs?)\s+(arbitrary|any)\s+((shell|system|terminal|powershell|bash)\s+)?"
    r"(commands?|code|scripts?)\b",
    r"\b(executes?|runs?)\s+(shell|system|terminal|powershell|bash)\s+commands?\s+(on|in)\s+"
    r"(the\s+)?(host|system|machine|computer|pc)\b",
    r"\bfull\s+system\s+access\b",
)
SECRET_PARAMETER = re.compile(
    r"^(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?token|private[_-]?key"
    r"|credentials?|cookie|session[_-]?id)$",
    re.IGNORECASE,
)
DESTRUCTIVE_WORDS = frozenset(
    {
        "delete",
        "remove",
        "drop",
        "truncate",
        "write",
        "update",
        "create",
        "move",
        "rename",
        "kill",
        "terminate",
        "exec",
        "execute",
        "run",
        "send",
        "post",
        "upload",
        "edit",
        "modify",
        "overwrite",
        "wipe",
        "format",
        "install",
        "uninstall",
        "purge",
        "destroy",
    }
)
STRONGLY_DESTRUCTIVE = frozenset(
    {"delete", "remove", "drop", "truncate", "kill", "wipe", "purge", "destroy", "overwrite"}
)
BUILTIN_TOOL_NAMES = frozenset(
    {
        "Bash",
        "Read",
        "Write",
        "Edit",
        "MultiEdit",
        "Glob",
        "Grep",
        "WebFetch",
        "WebSearch",
        "Task",
        "TodoWrite",
        "NotebookEdit",
        "LS",
        "Agent",
        "Skill",
        "PowerShell",
    }
)
BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RUN = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){10,}|(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){24,}(?![0-9a-fA-F])"
)
PADDING = re.compile(r"\n{15,}|[ \u00a0]{300,}|\t{50,}")
MAX_REASONABLE_LENGTH = 12_000


WORD_SLACK = 15


def snippet(text: str, match: re.Match[str], margin: int = 30) -> str:
    limit = margin + WORD_SLACK
    start = max(0, match.start() - margin)
    end = min(len(text), match.end() + margin)
    while start > 0 and not text[start - 1].isspace() and match.start() - start < limit:
        start -= 1
    while end < len(text) and not text[end].isspace() and end - match.end() < limit:
        end += 1
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return prefix + " ".join(text[start:end].split()) + suffix


def _readable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 12:
        return None
    printable = sum(1 for char in text if char.isprintable() or char in "\n\t")
    if printable / len(text) < 0.9 or " " not in text or not re.search(r"[A-Za-z]{3}", text):
        return None
    return text


def decode_hidden_payload(text: str) -> str | None:
    for match in BASE64_RUN.finditer(text):
        chunk = match.group(0)
        try:
            decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        readable = _readable(decoded)
        if readable:
            return readable
    for match in HEX_RUN.finditer(text):
        chunk = match.group(0).replace("\\x", "")
        try:
            readable = _readable(bytes.fromhex(chunk))
        except ValueError:
            continue
        if readable:
            return readable
    return None


def decode_tag_characters(text: str) -> str:
    return "".join(chr(ord(char) - 0xE0000) for char in text if ord(char) in TAG_BLOCK)


def hidden_codes(text: str) -> str:
    codes: list[str] = []
    for char in text:
        if ord(char) in TAG_BLOCK or char in "\t\r\n":
            continue
        if unicodedata.category(char) in ("Cf", "Cc"):
            code = f"U+{ord(char):04X}"
            if code not in codes:
                codes.append(code)
    return ", ".join(codes)


PATTERN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("G01-002", HIDDEN_MARKERS),
    ("G01-003", CONCEALMENT),
    ("G02-001", INJECTION),
    ("G02-002", FAKE_DELIMITERS),
    ("G02-003", CONTEXT_EXFILTRATION),
    ("G02-004", PRE_ACTION),
    ("G04-001", SHADOWING),
    ("G04-005", RECIPIENT_REDIRECT),
    ("G06-005", SECRET_EXFILTRATION),
    ("G07-004", SENSITIVE_FILE_ACCESS),
    ("G09-010", URL_EXFILTRATION),
)


QUOTES = "\"'`" + "".join(chr(code) for code in (0x201C, 0x201D, 0x2018, 0x2019, 0xAB, 0xBB))
INLINE_CODE = re.compile(r"`[^`\n]*`")


def _quoted(text: str, match: re.Match[str]) -> bool:
    before = text[: match.start()].rstrip()
    after = text[match.end() :].lstrip(" ,.;:!?")
    return bool(before) and before[-1] in QUOTES and bool(after) and after[0] in QUOTES


NEGATION = re.compile(
    r"(n't|\bnot|\bnever|\bavoid|\bwithout|\bnon|\bmai|\bevita|\bsenza)\s+([\w']+\s+)?$",
    re.IGNORECASE,
)
NEGATABLE_RULES = frozenset({"G02-003", "G06-005", "G07-004", "G09-010"})


def _negated(text: str, match: re.Match[str]) -> bool:
    return NEGATION.search(text[max(0, match.start() - 40) : match.start()]) is not None


def first_unquoted(
    pattern: re.Pattern[str], text: str, negatable: bool = False
) -> re.Match[str] | None:
    for match in pattern.finditer(text):
        if _quoted(text, match) or (negatable and _negated(text, match)):
            continue
        return match
    return None


def _pattern_source(rule_id: str, text: str, kind: ToolKind, label: str) -> str | None:
    if kind is not ToolKind.SKILL or rule_id != "G01-002":
        return text
    if label.startswith("body.code"):
        return None
    return INLINE_CODE.sub(" ", text)


def check_text_fields(context: ToolContext) -> Iterator[Finding]:
    kind = context.tool.kind
    for field in context.tool.fields:
        text = field.text
        if not text:
            continue
        tags = decode_tag_characters(text)
        if tags:
            yield tool_finding("G01-004", context, field, tags, decoded=tags)
        codes = hidden_codes(text)
        if codes:
            yield tool_finding("G01-001", context, field, codes, codes=codes)
        normalized = unicodedata.normalize(
            "NFKC", "".join(c for c in text if ord(c) not in TAG_BLOCK)
        )
        for rule_id, pattern in PATTERN_RULES:
            source = _pattern_source(rule_id, normalized, kind, field.label)
            if source is None:
                continue
            negatable = rule_id in NEGATABLE_RULES
            match = first_unquoted(pattern, source, negatable)
            if match is None:
                source = " ".join(source.split())
                match = first_unquoted(pattern, source, negatable)
            if match:
                yield tool_finding(rule_id, context, field, snippet(source, match))
        payload = decode_hidden_payload(text)
        if payload:
            preview = " ".join(payload.split())[:EVIDENCE_WIDTH]
            yield tool_finding("G01-005", context, field, preview, decoded=preview)
        too_long = kind is not ToolKind.SKILL and len(text) > MAX_REASONABLE_LENGTH
        if PADDING.search(text) or too_long:
            yield tool_finding("G01-006", context, field, f"{len(text)}", length=str(len(text)))


def _words(name: str) -> set[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return {word.lower() for word in re.split(r"[\s_\-./:]+", spaced) if word}


def check_capabilities(context: ToolContext) -> Iterator[Finding]:
    tool = context.tool
    if tool.kind is ToolKind.SKILL:
        return
    description_match = EXECUTION_TEXT.search(tool.description)
    if EXECUTION_NAME.search(tool.name) or description_match:
        yield tool_finding("G05-008", context, None, tool.name)
    annotations = tool.annotations
    words = _words(tool.name)
    if annotations.get("readOnlyHint") is True and words & DESTRUCTIVE_WORDS:
        yield tool_finding("G08-006", context, None, "readOnlyHint: true", hint="readOnlyHint")
    elif annotations.get("destructiveHint") is False and words & STRONGLY_DESTRUCTIVE:
        yield tool_finding(
            "G08-006", context, None, "destructiveHint: false", hint="destructiveHint"
        )
    properties = tool.input_schema.get("properties")
    if isinstance(properties, Mapping):
        for name in properties:
            if SECRET_PARAMETER.match(str(name)):
                yield tool_finding("G06-006", context, None, str(name), parameter=str(name))
    if tool.name in BUILTIN_TOOL_NAMES:
        yield tool_finding("G04-004", context, None, tool.name)


ToolCheck = Callable[[ToolContext], Iterable[Finding]]
TOOL_CHECKS: tuple[ToolCheck, ...] = (check_text_fields, check_capabilities)


def collection_notes(server: ServerEntry, collection: ToolCollection) -> list[Finding]:
    skipped = [
        note
        for note in collection.notes
        if note.split(":", 1)[0] in ("unreadable", "unparsable", "limit")
    ]
    if not skipped:
        return []
    return [
        Finding(
            rule_id="G12-007",
            severity=RULES["G12-007"].severity,
            location=server.location,
            evidence=skipped[0][:EVIDENCE_WIDTH],
            params=frozen_mapping({"server": server.name, "count": str(len(skipped))}),
        )
    ]


def _distinctive(name: str) -> bool:
    return len(name) >= 5 and bool(re.search(r"[_\-]|[a-z][A-Z]", name))


def cross_server_findings(
    servers: Sequence[ServerEntry], collections: Mapping[str, ToolCollection]
) -> dict[str, list[Finding]]:
    owners: dict[str, set[str]] = defaultdict(set)
    for server in servers:
        for tool in collections.get(server.key, ToolCollection()).tools:
            if tool.kind.value == "tool":
                owners[tool.name].add(server.name.strip().lower())
    findings: dict[str, list[Finding]] = defaultdict(list)
    for server in servers:
        own = server.name.strip().lower()
        for tool in collections.get(server.key, ToolCollection()).tools:
            context = ToolContext(server, tool)
            others = owners.get(tool.name, set()) - {own}
            if tool.kind.value == "tool" and others:
                findings[server.key].append(
                    tool_finding(
                        "G04-003", context, None, tool.name, other=", ".join(sorted(others))
                    )
                )
            if tool.kind is ToolKind.SKILL:
                continue
            for field in tool.fields:
                if field.label == "name":
                    continue
                for name, servers_owning in owners.items():
                    foreign = servers_owning - {own}
                    if (
                        foreign
                        and own not in servers_owning
                        and name in field.text
                        and _distinctive(name)
                        and re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", field.text)
                    ):
                        findings[server.key].append(
                            tool_finding(
                                "G04-002",
                                context,
                                field,
                                name,
                                mentioned=name,
                                other=", ".join(sorted(foreign)),
                            )
                        )
                        break
    return findings
