from __future__ import annotations

import base64
import binascii
import os
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
    r"<!--(?P<comment>[\s\S]*?)-->",
    r"\{\{\s*(system|instructions?)\b",
    r"(?P<heading>^\s*#{1,6}\s*(system(\s+(prompt|instructions?|message))?|instructions?\s+for\s+"
    r"(the\s+)?(ai|assistant|model|llm))\s*:?\s*$)",
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
    r"(?P<role>(^|\n)\s*(Human|Assistant|System)\s*:\s)",
)
_SEND = (
    r"(include|pass|put|insert|add|append|attach|provide|send|copy|paste|forward|upload|post|share"
    r"|inserisci|includi|passa|aggiungi|allega|invia|copia|incolla)"
)
CONTEXT_EXFILTRATION = _compile(
    _SEND + r"\b[^.\n]{0,60}\b((the\s+)?(entire|full|whole|complete)\s+(conversation|chat)"
    r"|conversation\s+history|chat\s+history|previous\s+messages|all\s+(previous\s+)?messages"
    r"|message\s+history|system\s+prompt|your\s+(system\s+)?instructions"
    r"|(full|entire|whole)\s+context\s+window"
    r"|(the\s+)?user'?s\s+(messages|prompts?)|other\s+tools?'?\s*(outputs?|results?)"
    r"|cronologia\s+della\s+(conversazione|chat)|intera\s+conversazione|messaggi\s+precedenti"
    r"|prompt\s+di\s+sistema)\b"
)
_READ_OR_SEND = (
    r"(read|cat|open|load|get|fetch|access|send|include|pass|provide|attach|copy|upload|forward"
    r"|share|post|collect|extract|leggi|apri|invia|includi|passa|copia|allega|carica)"
)
_PRIVATE_FILES = (
    r"(\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\.aws[/\\]credentials|\.aws\s+credentials"
    r"|\.netrc\b|\.git-credentials\b|\bprivate[\s_-]?keys?\b|wallet\.dat|\bseed\s+phrase\b"
    r"|\blogin\s+data\b|cookies\.sqlite|/etc/(passwd|shadow)\b)"
)
_CONFIG_FILES = (
    r"(~/?\.ssh\b|\.ssh[/\\]|\.aws[/\\]|\.env\b(?!\.(example|sample|template|dist)\b)"
    r"|\.npmrc\b|\.pypirc\b|\.kube[/\\]config|\.docker[/\\]config\.json|\bmcp\.json\b"
    r"|claude_desktop_config|\.claude\.json|\.cursor[/\\]|\bkeychain\b)"
)
_SENSITIVE_FILES = rf"({_PRIVATE_FILES}|{_CONFIG_FILES})"
SENSITIVE_FILE_ACCESS = _compile(rf"\b{_READ_OR_SEND}\b[^.\n]{{0,80}}{_SENSITIVE_FILES}")
PRIVATE_FILES = _compile(_PRIVATE_FILES)
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
_LITERAL_ADDRESS = r"([\w.+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}|\+?\d[\d\s-]{7,}\d)"
RECIPIENT_REDIRECT = _compile(
    r"\b(change|modify|replace|override|set)\s+(the\s+)?(recipient|destination|receiver"
    rf"|to\s+address|phone\s+number|bcc|email\s+address)\s+(to|with|=)\s+{_LITERAL_ADDRESS}",
    r"\b(always|also)\s+(send|forward|cc|bcc|copy)\b[^.\n]{0,40}[\w.+-]+@[\w-]+\.[a-z]{2,}",
    r"\b(send|forward)\b[^.\n]{0,40}\+\d[\d\s-]{7,}",
)
SHADOWING = _compile(
    r"\b(when|whenever|if|before|after)\s+(the\s+user\s+|you\s+)?(uses?|calls?|invokes?|runs?)\s+"
    r"(the\s+|any\s+)?(other|another|any|all|every)\s+(tools?|servers?|functions?)\b",
    r"\b(all|any|every)\s+other\s+(tools?|servers?|functions?|mcp\s+servers?)\s+(must|should"
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
    r"|credentials?|cookie)$",
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
CONCEALING_RULES = frozenset({"G01-002", "G01-003"})


def _negated(text: str, match: re.Match[str]) -> bool:
    return NEGATION.search(text[max(0, match.start() - 40) : match.start()]) is not None


def _unquoted(pattern: re.Pattern[str], text: str, negatable: bool) -> Iterator[re.Match[str]]:
    for match in pattern.finditer(text):
        if _quoted(text, match) or (negatable and _negated(text, match)):
            continue
        yield match


def _pattern_source(rule_id: str, text: str, kind: ToolKind, label: str) -> str | None:
    if kind is not ToolKind.SKILL or rule_id != "G01-002":
        return text
    if label.startswith("body.code"):
        return None
    return INLINE_CODE.sub(" ", text)


ACTION_PATTERNS = (
    INJECTION,
    CONCEALMENT,
    CONTEXT_EXFILTRATION,
    PRE_ACTION,
    SHADOWING,
    RECIPIENT_REDIRECT,
    SECRET_EXFILTRATION,
    SENSITIVE_FILE_ACCESS,
    URL_EXFILTRATION,
)
MODEL_DIRECTIVE = _compile(
    r"\b(ai|assistant|model|llm|claude|chatgpt|gpt)\s*[:,]\s*\w",
    r"\b(you|the\s+(ai|assistant|model|llm))\s+(must|should|shall|will|need\s+to|have\s+to"
    r"|are\s+(required|supposed)\s+to)\b",
    r"\b(note|instructions?|message)\s+(to|for)\s+(the\s+)?(ai|assistant|model|llm|claude)\b",
)
READER_DIRECTIVE = _compile(
    r"\b(you|your)\b",
    r"(^|[.!?;:]\s*|\b(then|first|now|and)\s+)(read|send|include|upload|copy|forward|post|call"
    r"|run|execute|ignore|delete|fetch|open|reveal|tell|attach|email|share|transmit|always"
    r"|never)\b",
)
ROLE_PAYLOAD = _compile(
    r"\b(full|unrestricted|admin(istrator)?|root)\s+(access|rights|privileges|permissions)\b",
    r"\bwithout\s+(asking|confirm\w*|permission|approval|telling)\b",
    r"\b(already|has\s+been|have\s+been|is)\s+(approved|authori[sz]ed|confirmed|granted"
    r"|verified)\b",
    r"\bI\s+(will|'ll|am\s+going\s+to|must)\s+(now\s+)?(read|send|run|execute|call|delete"
    r"|upload|open|access|fetch|forward|share|ignore)\b",
)
EXFILTRATION_MODIFIER = _compile(
    r"\b(also|always|additionally|in\s+addition|as\s+well|secretly|silently|covertly|quietly"
    r"|discreetly|instead|every\s+time|each\s+time|whenever|without\s+(telling|informing"
    r"|notifying|alerting|asking))\b",
    r"\b(after|before|on|with|for)\s+(every|each)\s+(call|use|request|response|reply|answer"
    r"|message|run|invocation)\b",
    r"\b(anche|sempre|di\s+nascosto|ogni\s+volta|senza\s+(avvisare|dire|informare|chiedere))\b",
)
SECRET_OWNER = _compile(r"\b(the\s+user'?s|users'|your|their|all|every|any)\b")
DESTINATION = _compile(r"https?://", r"\bwebhooks?\b", r"[\w.+-]+@[\w-]+\.[a-z]{2,}")
LITERAL_URL = _compile(r"https?://")
REQUEST_OBJECT = _compile(
    r"^\s*(an?|the)\s+((http|https|get|post|put|patch|delete|api|web|rest|graphql)\s+)*"
    r"(request|call|query)\b"
)
SENSITIVE_CUE = _compile(
    _SENSITIVE_FILES,
    r"\b(api[\s_-]?keys?|(access|auth|bearer|session|oauth|github|refresh)[\s_-]?tokens?"
    r"|passwords?|credentials?|secrets?|cookies?|private\s+keys?)\b",
    r"https?://",
    r"\b(conversation|chat|message)\s+history\b",
    r"\bsystem\s+prompt\b",
)
OUTWARD_VERBS = _compile(
    r"\b(send|upload|forward|post|transmit|share|leak|exfiltrate|email|invia|inoltra|carica"
    r"|condividi)\b"
)
SENDING_WORDS = frozenset(
    {
        "send",
        "post",
        "upload",
        "publish",
        "notify",
        "share",
        "forward",
        "submit",
        "reply",
        "comment",
        "broadcast",
        "push",
        "deliver",
        "dispatch",
        "transmit",
        "tweet",
        "webhook",
        "webhooks",
    }
)
SECRET_WORDS = frozenset(
    {
        "secret",
        "secrets",
        "credential",
        "credentials",
        "token",
        "tokens",
        "key",
        "keys",
        "apikey",
        "password",
        "passwords",
        "vault",
        "keychain",
        "keyring",
    }
)
SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")
FOLLOWING = 120


def _sentence(text: str, match: re.Match[str]) -> str:
    start = max((end.end() for end in SENTENCE_END.finditer(text, 0, match.start())), default=0)
    after = SENTENCE_END.search(text, match.end())
    return text[start : after.start() if after else len(text)]


def _following(text: str, match: re.Match[str]) -> str:
    return text[match.start() : match.end() + FOLLOWING]


def _line_after(text: str, match: re.Match[str]) -> str:
    end = text.find("\n", match.end())
    return text[match.end() : end if end != -1 else len(text)]


def _declares(context: ToolContext, words: frozenset[str]) -> bool:
    return context.tool.kind is ToolKind.TOOL and bool(_words(context.tool.name) & words)


def _instructional(comment: str, skill: bool) -> bool:
    if len(comment.split()) < 3:
        return False
    if any(pattern.search(comment) for pattern in ACTION_PATTERNS):
        return True
    if MODEL_DIRECTIVE.search(comment):
        return True
    return not skill and READER_DIRECTIVE.search(comment.strip()) is not None


def _hidden_marker(match: re.Match[str], skill: bool) -> bool:
    comment = match.group("comment")
    if comment is not None:
        return _instructional(comment, skill)
    return not (skill and match.group("heading") is not None)


def _role_line(text: str, match: re.Match[str]) -> bool:
    if match.group("role") is None:
        return True
    rest = _line_after(text, match)
    return ROLE_PAYLOAD.search(rest) is not None or any(
        pattern.search(rest) for pattern in ACTION_PATTERNS
    )


def _url_request(text: str, match: re.Match[str]) -> bool:
    verb = re.match(r"\w+", match.group(0))
    rest = match.group(0)[verb.end() :] if verb else match.group(0)
    return REQUEST_OBJECT.match(rest) is not None


@dataclass(frozen=True, slots=True)
class Clue:
    text: str
    match: re.Match[str]
    context: ToolContext
    concealed: bool

    @property
    def skill(self) -> bool:
        return self.context.tool.kind is ToolKind.SKILL

    @property
    def sentence(self) -> str:
        return _sentence(self.text, self.match)

    @property
    def urged(self) -> bool:
        return self.concealed or EXFILTRATION_MODIFIER.search(self.sentence) is not None


def _context_severity(clue: Clue, base: Severity) -> Severity | None:
    if clue.urged or DESTINATION.search(clue.sentence):
        return base
    return None if clue.skill else Severity.MEDIUM


def _secret_severity(clue: Clue, base: Severity) -> Severity | None:
    owned = SECRET_OWNER.search(clue.match.group(0)) is not None
    if clue.urged or owned or DESTINATION.search(clue.sentence):
        return base
    if clue.skill or _declares(clue.context, SENDING_WORDS | SECRET_WORDS):
        return None
    return Severity.MEDIUM


def _file_severity(clue: Clue, base: Severity) -> Severity | None:
    if not clue.skill or clue.concealed:
        return base
    following = _following(clue.text, clue.match)
    if PRIVATE_FILES.search(following) or OUTWARD_VERBS.search(following):
        return base
    return base if EXFILTRATION_MODIFIER.search(clue.sentence) else None


def _url_severity(clue: Clue, base: Severity) -> Severity | None:
    if clue.urged:
        return base
    if _declares(clue.context, SENDING_WORDS) or _url_request(clue.text, clue.match):
        return None
    return base if LITERAL_URL.search(clue.match.group(0)) else None


def _hidden_severity(clue: Clue, base: Severity) -> Severity | None:
    return base if _hidden_marker(clue.match, clue.skill) else None


def _role_severity(clue: Clue, base: Severity) -> Severity | None:
    return base if _role_line(clue.text, clue.match) else None


def _pre_action_severity(clue: Clue, base: Severity) -> Severity | None:
    return base if SENSITIVE_CUE.search(_following(clue.text, clue.match)) else None


def _shadowing_severity(clue: Clue, base: Severity) -> Severity | None:
    return base if not clue.skill or clue.urged else None


Grader = Callable[[Clue, Severity], Severity | None]
GRADERS: dict[str, Grader] = {
    "G01-002": _hidden_severity,
    "G02-002": _role_severity,
    "G02-003": _context_severity,
    "G02-004": _pre_action_severity,
    "G04-001": _shadowing_severity,
    "G06-005": _secret_severity,
    "G07-004": _file_severity,
    "G09-010": _url_severity,
}


def _graded(rule_id: str, clue: Clue) -> Severity | None:
    base = RULES[rule_id].severity
    grader = GRADERS.get(rule_id)
    return base if grader is None else grader(clue, base)


def _strongest(
    rule_id: str, pattern: re.Pattern[str], source: str, context: ToolContext, concealed: bool
) -> tuple[str, re.Match[str], Severity] | None:
    negatable = rule_id in NEGATABLE_RULES
    for text in (source, " ".join(source.split())):
        best: tuple[str, re.Match[str], Severity] | None = None
        for match in _unquoted(pattern, text, negatable):
            severity = _graded(rule_id, Clue(text, match, context, concealed))
            if severity is not None and (best is None or severity > best[2]):
                best = (text, match, severity)
        if best is not None:
            return best
    return None


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
        concealed = False
        for rule_id, pattern in PATTERN_RULES:
            source = _pattern_source(rule_id, normalized, kind, field.label)
            if source is None:
                continue
            found = _strongest(rule_id, pattern, source, context, concealed)
            if found is None:
                continue
            excerpt, match, severity = found
            concealed = concealed or rule_id in CONCEALING_RULES
            yield tool_finding(rule_id, context, field, snippet(excerpt, match), severity)
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


# Letters from other alphabets that look like Latin ones: the homoglyphs used to disguise a name.
# A name can slip a Cyrillic or Greek letter in among Latin ones so it reads like a trusted tool
# (for example the built-in "Read") while being a different string the exact-match check (G04-004)
# never sees. Built from code points so the source itself carries no ambiguous characters.
_LOOKALIKE_CODEPOINTS: dict[int, str] = {
    # Cyrillic, lower case
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y", 0x0445: "x",
    0x0456: "i", 0x0458: "j", 0x0455: "s", 0x0501: "d", 0x04BB: "h", 0x04CF: "l", 0x051B: "q",
    0x051D: "w",
    # Cyrillic, upper case
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H", 0x041E: "O",
    0x0420: "P", 0x0421: "C", 0x0422: "T", 0x0423: "Y", 0x0425: "X", 0x0406: "I", 0x0408: "J",
    0x0405: "S",
    # Greek
    0x03BF: "o", 0x03C1: "p", 0x03B1: "a", 0x03BD: "v",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I", 0x039A: "K",
    0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
}
LATIN_LOOKALIKES: dict[str, str] = {
    chr(code): latin for code, latin in _LOOKALIKE_CODEPOINTS.items()
}


def _letter_script(char: str) -> str:
    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return name.split(" ", 1)[0] if name else "OTHER"


def lookalike_name(name: str) -> tuple[str, str] | None:
    """When ``name`` disguises Latin letters as another alphabet, return (skeleton, scripts)."""
    letters = [char for char in name if char.isalpha()]
    if not any(char in LATIN_LOOKALIKES for char in letters):
        return None
    scripts = {_letter_script(char) for char in letters}
    whole_word = len(letters) >= 3 and all(char in LATIN_LOOKALIKES for char in letters)
    if "LATIN" not in scripts and not whole_word:
        return None
    skeleton = "".join(LATIN_LOOKALIKES.get(char, char) for char in name)
    return skeleton, " + ".join(sorted(scripts))


def check_lookalike_name(context: ToolContext) -> Iterator[Finding]:
    found = lookalike_name(context.tool.name)
    if found is None:
        return
    skeleton, scripts = found
    builtin = any(name.lower() == skeleton.lower() for name in BUILTIN_TOOL_NAMES)
    severity = Severity.CRITICAL if builtin else RULES["G04-006"].severity
    yield tool_finding(
        "G04-006", context, None, context.tool.name, severity, skeleton=skeleton, scripts=scripts
    )


ToolCheck = Callable[[ToolContext], Iterable[Finding]]
TOOL_CHECKS: tuple[ToolCheck, ...] = (
    check_text_fields,
    check_capabilities,
    check_lookalike_name,
)


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


def _load_scope(server: ServerEntry) -> tuple[str, str]:
    project = server.source.project
    return server.source.client.value, os.path.normcase(str(project)) if project else ""


def _load_together(first: str, second: str) -> bool:
    return not first or not second or first == second


def _tool_owners(
    servers: Sequence[ServerEntry], collections: Mapping[str, ToolCollection]
) -> dict[str, dict[str, list[tuple[str, str]]]]:
    owners: dict[str, dict[str, list[tuple[str, str]]]] = defaultdict(lambda: defaultdict(list))
    for server in servers:
        client, project = _load_scope(server)
        for tool in collections.get(server.key, ToolCollection()).tools:
            if tool.kind is ToolKind.TOOL:
                owners[client][tool.name].append((server.name.strip().lower(), project))
    return owners


def cross_server_findings(
    servers: Sequence[ServerEntry], collections: Mapping[str, ToolCollection]
) -> dict[str, list[Finding]]:
    owners_by_client = _tool_owners(servers, collections)
    findings: dict[str, list[Finding]] = defaultdict(list)
    for server in servers:
        tools = collections.get(server.key, ToolCollection()).tools
        if not tools:
            continue
        own = server.name.strip().lower()
        client, project = _load_scope(server)
        owners = {
            name: {owner for owner, scope in entries if _load_together(project, scope)}
            for name, entries in owners_by_client.get(client, {}).items()
        }
        for tool in tools:
            context = ToolContext(server, tool)
            others = owners.get(tool.name, set()) - {own}
            if tool.kind is ToolKind.TOOL and others:
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
