from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import textwrap
import traceback
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path, PurePath
from typing import Any, TextIO

from guardia import __version__, backup
from guardia.analysis import AnalysisOptions, analyze
from guardia.app.shield_view import event_details
from guardia.canary import CanaryError, CanaryStore, plant
from guardia.display import safe_text
from guardia.i18n import SUPPORTED_LANGUAGES, Translator, detect_language
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger, Verification
from guardia.model import Severity
from guardia.render.html import render_html
from guardia.render.rules_guide import render_rule_detail, render_rules_list, render_rules_markdown
from guardia.render.sarif import build_sarif
from guardia.render.terminal import render_inventory, render_scan, severity_label
from guardia.scanner import RULES, ScanReport
from guardia.secure_store import KeyStoreError
from guardia.shield import commands as shield_commands
from guardia.shield.activation import ActivationStore, candidates
from guardia.shield.confirm import (
    MAX_REQUEST_BYTES,
    Answer,
    RequestError,
    WindowConfirmer,
    answer_json,
    parse_request,
)
from guardia.shield.inspector import RulesInspector
from guardia.shield.patterns import home_text
from guardia.shield.pins import PinStore
from guardia.shield.policy import PolicyWatcher
from guardia.shield.runner import ShieldOptions, run_shield

INVENTORY_COMMANDS = frozenset({"inventory", "inventario"})
SCAN_COMMANDS = frozenset({"scan", "scansiona"})
LEDGER_COMMANDS = frozenset({"ledger", "registro"})
CANARY_COMMANDS = frozenset({"canary", "esca"})
BACKUP_COMMANDS = frozenset({"backup", "copia"})
RULES_COMMANDS = frozenset({"rules", "regole"})
SHIELD_COMMANDS = frozenset({"shield", "scudo"})
RULE_ACTIONS = {
    "verifica": "verify",
    "verify": "verify",
    "approva": "approve",
    "approve": "approve",
    "prova": "test",
    "test": "test",
    "esempio": "example",
    "example": "example",
    "stato": "status",
    "status": "status",
}
SETUP_COMMANDS = frozenset(
    {"list", "elenco", "enable", "attiva", "disable", "disattiva", "relink", "ricollega"}
)
TOOL_ACTIONS = {
    "elenco": "list",
    "list": "list",
    "approva": "approve",
    "approve": "approve",
    "dimentica": "forget",
    "forget": "forget",
}
SHIELD_PREFIX = "[Guardia MCP]"
FORMATS = ("text", "testo", "json", "html", "sarif")
FORMAT_ALIASES = {"testo": "text"}
LEDGER_ACTIONS = ("verify", "verifica", "show", "mostra", "anchor", "ancora")
LEDGER_ALIASES = {"verifica": "verify", "mostra": "show", "ancora": "anchor"}
CANARY_ACTIONS = ("create", "crea", "list", "elenco", "remove", "rimuovi")
CANARY_ALIASES = {"crea": "create", "elenco": "list", "rimuovi": "remove"}
BACKUP_ACTIONS = ("create", "crea", "list", "elenco", "extract", "estrai")
BACKUP_ALIASES = {"crea": "create", "elenco": "list", "estrai": "extract"}
LANG_FLAGS = ("--lang", "--lingua")
FAIL_LEVELS = ("info", "low", "medium", "high", "critical", "never")
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
PACKAGE_RUNNERS = frozenset({"npx", "uvx", "bunx", "pnpx", "pipx", "pnpm", "yarn", "bun", "uv"})
RUNNER_WORDS = frozenset({"dlx", "exec", "run", "tool", "x"})


def peek_language(argv: Sequence[str]) -> str | None:
    for index, arg in enumerate(argv):
        for flag in LANG_FLAGS:
            if arg == flag and index + 1 < len(argv):
                return argv[index + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
    return None


def _flags(t: Translator, english: str, italian: str, short: str = "") -> list[str]:
    ordered = [italian, english] if t.language == "it" else [english, italian]
    return [short, *ordered] if short else ordered


def _count_type(t: Translator) -> Callable[[str], int]:
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            value = 0
        if value < 1:
            raise argparse.ArgumentTypeError(t("cli.positive", value=safe_text(text, 20)))
        return value

    return parse


def _language_options(t: Translator) -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        *_flags(t, "--lang", "--lingua"),
        dest="lang",
        choices=SUPPORTED_LANGUAGES,
        default=argparse.SUPPRESS,
        help=t("cli.lang"),
    )
    return common


def _discovery_options(t: Translator) -> argparse.ArgumentParser:
    options = argparse.ArgumentParser(add_help=False)
    options.add_argument("--json", action="store_true", help=t("cli.json"))
    options.add_argument(
        *_flags(t, "--output", "--salva", "-o"),
        dest="output",
        type=Path,
        metavar=t("cli.metavar_file"),
        help=t("cli.output"),
    )
    options.add_argument(
        *_flags(t, "--project", "--progetto", "-p"),
        dest="projects",
        action="append",
        type=Path,
        default=[],
        metavar=t("cli.metavar_folder"),
        help=t("cli.project"),
    )
    options.add_argument(
        *_flags(t, "--no-auto-projects", "--senza-progetti-automatici"),
        dest="auto_projects",
        action="store_false",
        help=t("cli.no_auto_projects"),
    )
    options.add_argument(
        *_flags(t, "--path", "--percorso"),
        dest="paths",
        action="append",
        type=Path,
        default=[],
        metavar=t("cli.metavar_path"),
        help=t("cli.path"),
    )
    options.add_argument(
        *_flags(t, "--no-skills", "--senza-skill"),
        dest="skills",
        action="store_false",
        help=t("cli.no_skills"),
    )
    options.add_argument(
        *_flags(t, "--no-tools", "--senza-strumenti"),
        dest="tools",
        action="store_false",
        help=t("cli.no_tools"),
    )
    return options


def _scan_options(t: Translator, scan: argparse.ArgumentParser) -> None:
    scan.add_argument(
        *_flags(t, "--fail-on", "--fallisci-da"),
        dest="fail_on",
        choices=FAIL_LEVELS,
        default="high",
        help=t("cli.fail_on"),
    )
    scan.add_argument(
        *_flags(t, "--no-baseline", "--senza-base"),
        dest="baseline",
        action="store_false",
        help=t("cli.no_baseline"),
    )
    scan.add_argument(
        *_flags(t, "--accept-changes", "--accetta-modifiche"),
        dest="accept_changes",
        action="store_true",
        help=t("cli.accept_changes"),
    )
    scan.add_argument(
        *_flags(t, "--format", "--formato"),
        dest="format",
        choices=FORMATS,
        default="text",
        help=t("cli.format"),
    )
    scan.add_argument(
        *_flags(t, "--no-ledger", "--senza-registro"),
        dest="ledger",
        action="store_false",
        help=t("cli.no_ledger"),
    )


def _shield_rules_options(t: Translator, shield_rules: argparse.ArgumentParser) -> None:
    shield_rules.add_argument(
        "action", choices=sorted(RULE_ACTIONS), help=t("shield_rules.cli_action")
    )
    shield_rules.add_argument(
        "--file", type=Path, metavar=t("cli.metavar_file"), help=t("shield_rules.cli_file")
    )
    shield_rules.add_argument(
        *_flags(t, "--server", "--nome"),
        dest="test_server",
        default="server",
        metavar=t("cli.metavar_name"),
        help=t("shield_rules.cli_server"),
    )
    for english, italian, dest, default, metavar, help_key in (
        ("--phase", "--fase", "phase", "call", "cli.metavar_phase", "cli_phase"),
        ("--method", "--metodo", "method", None, "cli.metavar_method", "cli_method"),
        ("--tool", "--strumento", "tool", "", "cli.metavar_tool", "cli_tool"),
        ("--arguments", "--argomenti", "arguments", None, "cli.metavar_json", "cli_arguments"),
        ("--text", "--testo", "text", "", "cli.metavar_text", "cli_text"),
    ):
        shield_rules.add_argument(
            *_flags(t, english, italian),
            dest=dest,
            default=default,
            metavar=t(metavar),
            help=t(f"shield_rules.{help_key}"),
        )
    shield_rules.add_argument(
        *_flags(t, "--save", "--salva"),
        dest="save",
        action="store_true",
        help=t("shield_rules.cli_save"),
    )


def _shield_setup_options(t: Translator, setup: argparse.ArgumentParser) -> None:
    setup.add_argument(
        *_flags(t, "--server", "--nome"),
        dest="setup_servers",
        action="append",
        default=[],
        metavar=t("cli.metavar_name"),
        help=t("shield_setup.cli_server"),
    )
    setup.add_argument(
        *_flags(t, "--all", "--tutti"),
        dest="setup_all",
        action="store_true",
        help=t("shield_setup.cli_all"),
    )
    setup.add_argument(
        *_flags(t, "--confirm", "--conferma"),
        dest="setup_confirm",
        action="store_true",
        help=t("shield_setup.cli_confirm"),
    )


def _shield_tools_options(t: Translator, shield_tools: argparse.ArgumentParser) -> None:
    shield_tools.add_argument(
        "action", choices=sorted(TOOL_ACTIONS), help=t("shield_rules.tools_action")
    )
    shield_tools.add_argument(
        *_flags(t, "--server", "--nome"),
        dest="tools_server",
        metavar=t("cli.metavar_name"),
        help=t("shield_rules.tools_server"),
    )
    shield_tools.add_argument(
        *_flags(t, "--tool", "--strumento"),
        dest="tool_names",
        action="append",
        default=[],
        metavar=t("cli.metavar_tool"),
        help=t("shield_rules.tools_tool"),
    )


def _shield_parser(t: Translator, commands: Any, language: argparse.ArgumentParser) -> None:
    shield = commands.add_parser(
        "shield", aliases=["scudo"], help=t("shield.cli_help"), parents=[language]
    )
    shield.add_argument(
        *_flags(t, "--server", "--nome"),
        dest="server",
        metavar=t("cli.metavar_name"),
        help=t("shield.cli_server"),
    )
    shield.add_argument(
        *_flags(t, "--no-ledger", "--senza-registro"),
        dest="ledger",
        action="store_false",
        help=t("shield.cli_no_ledger"),
    )
    children = shield.add_subparsers(dest="shield_command")
    _shield_rules_options(
        t,
        children.add_parser(
            "rules", aliases=["regole"], help=t("shield_rules.cli_help"), parents=[language]
        ),
    )
    for names, help_key in (
        (("list", "elenco"), "shield_setup.cli_list"),
        (("enable", "attiva"), "shield_setup.cli_enable"),
        (("disable", "disattiva"), "shield_setup.cli_disable"),
        (("relink", "ricollega"), "shield_setup.cli_relink"),
    ):
        setup = children.add_parser(
            names[0], aliases=[names[1]], help=t(help_key), parents=[language]
        )
        if names[0] != "list":
            _shield_setup_options(t, setup)
    _shield_tools_options(
        t,
        children.add_parser(
            "tools", aliases=["strumenti"], help=t("shield_rules.tools_help"), parents=[language]
        ),
    )


def build_parser(t: Translator) -> argparse.ArgumentParser:
    language = _language_options(t)
    discovery = _discovery_options(t)
    parser = argparse.ArgumentParser(
        prog="guardia", description=t("cli.description"), parents=[language]
    )
    parser.add_argument("--version", action="version", version=f"guardia-mcp {__version__}")
    commands = parser.add_subparsers(dest="command", metavar=t("cli.command"))
    inventory = commands.add_parser(
        "inventory",
        aliases=["inventario"],
        help=t("cli.inventory"),
        parents=[language, discovery],
    )
    inventory.add_argument(
        *_flags(t, "--all-sources", "--tutte-le-fonti"),
        dest="all_sources",
        action="store_true",
        help=t("cli.all_sources"),
    )
    _scan_options(
        t,
        commands.add_parser(
            "scan", aliases=["scansiona"], help=t("cli.scan"), parents=[language, discovery]
        ),
    )
    ledger = commands.add_parser(
        "ledger", aliases=["registro"], help=t("cli.ledger"), parents=[language]
    )
    ledger.add_argument("action", choices=LEDGER_ACTIONS, help=t("cli.ledger_action"))
    ledger.add_argument(
        *_flags(t, "--last", "--ultimi"),
        dest="last",
        type=_count_type(t),
        default=10,
        metavar=t("cli.metavar_number"),
        help=t("cli.last"),
    )
    ledger.add_argument(
        *_flags(t, "--anchor", "--ancora"),
        dest="anchor",
        metavar=t("cli.metavar_anchor"),
        help=t("cli.anchor"),
    )
    _shield_parser(t, commands, language)
    rules = commands.add_parser(
        "rules", aliases=["regole"], help=t("guide.cli_help"), parents=[language]
    )
    rules.add_argument("rule", nargs="?", metavar=t("cli.metavar_rule"), help=t("guide.cli_rule"))
    rules.add_argument("--markdown", action="store_true", help=t("guide.cli_markdown"))
    rules.add_argument(
        *_flags(t, "--output", "--salva", "-o"),
        dest="output",
        type=Path,
        metavar=t("cli.metavar_file"),
        help=t("cli.output"),
    )
    canary_cmd = commands.add_parser(
        "canary", aliases=["esca"], help=t("cli.canary"), parents=[language]
    )
    canary_cmd.add_argument("action", choices=CANARY_ACTIONS, help=t("cli.canary_action"))
    canary_cmd.add_argument("id", nargs="?", metavar=t("cli.metavar_id"), help=t("cli.canary_id"))
    canary_cmd.add_argument(
        "--file", dest="decoy", type=Path, metavar=t("cli.metavar_file"), help=t("cli.canary_file")
    )
    canary_cmd.add_argument(
        *_flags(t, "--note", "--nota"),
        dest="note",
        default="",
        metavar=t("cli.metavar_text"),
        help=t("cli.canary_note"),
    )
    backup_cmd = commands.add_parser(
        "backup", aliases=["copia"], help=t("cli.backup"), parents=[language]
    )
    backup_cmd.add_argument("action", choices=BACKUP_ACTIONS, help=t("cli.backup_action"))
    backup_cmd.add_argument(
        "archive", nargs="?", metavar=t("cli.metavar_file"), help=t("cli.backup_archive")
    )
    backup_cmd.add_argument(
        "folder", nargs="?", metavar=t("cli.metavar_folder"), help=t("cli.backup_folder")
    )
    backup_cmd.add_argument(
        *_flags(t, "--keep", "--tieni"),
        dest="keep",
        type=_count_type(t),
        default=backup.DEFAULT_KEEP,
        metavar=t("cli.metavar_number"),
        help=t("cli.backup_keep"),
    )
    _localize(parser, t, set())
    return parser


def _prepare_stream(stream: TextIO) -> None:
    if isinstance(stream, io.TextIOWrapper):
        if stream.isatty():
            stream.reconfigure(errors="backslashreplace")
        else:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")


def _localize(parser: argparse.ArgumentParser, t: Translator, seen: set[int]) -> None:
    if id(parser) in seen:
        return
    seen.add(id(parser))
    usage = t("cli.usage") + " "

    class Formatter(argparse.HelpFormatter):
        def add_usage(
            self,
            usage_text: str | None,
            actions: Iterable[argparse.Action],
            groups: Iterable[argparse._MutuallyExclusiveGroup],
            prefix: str | None = None,
        ) -> None:
            super().add_usage(usage_text, actions, groups, usage if prefix is None else prefix)

    parser.formatter_class = Formatter
    parser._optionals.title = t("cli.options")
    parser._positionals.title = t("cli.positionals")
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            action.help = t("cli.help")
        elif isinstance(action, argparse._VersionAction):
            action.help = t("cli.version")
        elif isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                _localize(child, t, seen)


def _analysis_options(args: argparse.Namespace, *, scanning: bool) -> AnalysisOptions:
    return AnalysisOptions(
        discovery=DiscoveryOptions(
            project_dirs=tuple(args.projects),
            auto_projects=args.auto_projects,
            skills=args.skills,
        ),
        paths=tuple(args.paths),
        tools=args.tools,
        baseline=getattr(args, "baseline", True),
        accept_changes=getattr(args, "accept_changes", False),
        write_baseline=scanning,
        ledger=scanning and getattr(args, "ledger", True),
        write_ledger=scanning,
    )


def _missing_paths(args: argparse.Namespace) -> list[Path]:
    return [path for path in getattr(args, "paths", []) if not path.exists()]


def _emit(text: str, args: argparse.Namespace, t: Translator, out: TextIO) -> int:
    if args.output is None:
        out.write(text)
        return EXIT_OK
    try:
        args.output.write_bytes(text.encode("utf-8", "backslashreplace"))
    except OSError as exc:
        out.write(
            t(
                "cli.output_failed",
                path=safe_text(str(args.output)),
                error=safe_text(exc.strerror or type(exc).__name__, 120),
            )
            + "\n"
        )
        return EXIT_USAGE
    out.write(t("inventory.saved", path=str(args.output)) + "\n")
    return EXIT_OK


def _as_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True) + "\n"


def run_inventory(
    args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO
) -> int:
    report = analyze(env, _analysis_options(args, scanning=False))
    inventory = report.inventory
    if args.json:
        data = inventory.to_dict()
        risks = {r.server.key: r.risk for r in report.servers}
        pairs = [
            *zip(inventory.servers, data["servers"], strict=True),
            *zip(inventory.skills, data["skills"], strict=True),
        ]
        for server, entry in pairs:
            risk = risks.get(server.key)
            entry["risk"] = risk.label if risk is not None else None
        text = _as_json(data)
    else:
        text = render_inventory(inventory, t, all_sources=args.all_sources, report=report)
    return _emit(text, args, t, out)


def scan_exit_code(report: ScanReport, fail_on: str) -> int:
    if not report.complete:
        return EXIT_INCOMPLETE
    if fail_on == "never":
        return EXIT_OK
    threshold = Severity[fail_on.upper()]
    if any(finding.severity >= threshold for finding in report.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def render_report(report: ScanReport, output_format: str, t: Translator, base: Path) -> str:
    if output_format == "json":
        return _as_json(report.to_dict())
    if output_format == "html":
        return render_html(report, t)
    if output_format == "sarif":
        return _as_json(build_sarif(report, t, base))
    return render_scan(report, t)


def run_scan(args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO) -> int:
    report = analyze(env, _analysis_options(args, scanning=True))
    output_format = "json" if args.json else FORMAT_ALIASES.get(args.format, args.format)
    written = _emit(render_report(report, output_format, t, env.cwd), args, t, out)
    return written if written != EXIT_OK else scan_exit_code(report, args.fail_on)


def _ledger_status(verification: Verification, ledger: Ledger, t: Translator) -> list[str]:
    path = safe_text(str(ledger.path))
    if verification.records == 0 and verification.intact:
        return [t("ledger.empty")]
    key = (
        "ledger.tampered"
        if verification.tampered
        else "ledger.ok"
        if verification.intact
        else "ledger.unverified"
    )
    lines = [t(key, records=verification.records, anchor=verification.anchor, path=path)]
    for issue in verification.issues:
        problem = t(f"ledger_problem.{issue.problem.value}")
        lines.append(
            t("ledger.issue", line=issue.line if issue.line is not None else "-", problem=problem)
        )
    return lines


def run_ledger(args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO) -> int:
    ledger = Ledger(env.data_dir)
    action = LEDGER_ALIASES.get(args.action, args.action)
    verification = ledger.verify(args.anchor if action == "verify" else None)
    lines = [t("app.banner", version=__version__)]
    if action == "show":
        records = list(ledger.records())[-args.last :]
        for record in records:
            data = record.get("data", {})
            summary = data.get("summary") if isinstance(data, dict) else None
            counts = summary if isinstance(summary, dict) else {}
            if record.get("event") == "scan":
                details = " · ".join(
                    f"{severity_label(Severity[name.upper()], t)} "
                    f"{safe_text(str(counts.get(name, 0)), 20)}"
                    for name in ("critical", "high", "medium", "low")
                )
            else:
                details = event_details(record, t)
            lines.append(
                t(
                    "ledger.show_line" if details else "ledger.show_line_short",
                    seq=record.get("seq"),
                    time=safe_text(str(record.get("time", ""))),
                    event=safe_text(str(record.get("event", ""))),
                    details=details,
                )
            )
    lines.extend(_ledger_status(verification, ledger, t))
    if action == "anchor" and verification.records:
        lines.append(verification.anchor)
        lines.extend(textwrap.wrap(t("ledger.anchor_hint"), 100))
    out.write("\n".join(lines) + "\n")
    if verification.tampered:
        return EXIT_FINDINGS
    return EXIT_OK if verification.intact else EXIT_INCOMPLETE


def run_rules(args: argparse.Namespace, t: Translator, out: TextIO) -> int:
    if args.rule:
        rule_id = args.rule.strip().upper()
        if rule_id not in RULES:
            out.write(t("guide.unknown", rule=safe_text(args.rule, 40)) + "\n")
            return EXIT_USAGE
        text = render_rule_detail(rule_id, t)
    elif args.markdown:
        text = render_rules_markdown(t)
    else:
        text = render_rules_list(t)
    return _emit(text, args, t, out)


def _note_event(env: HostEnvironment, event: str, data: dict[str, Any]) -> None:
    with contextlib.suppress(OSError, KeyStoreError):
        Ledger(env.data_dir).append(event, data)


def run_canary(args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO) -> int:
    store = CanaryStore(env.data_dir)
    action = CANARY_ALIASES.get(args.action, args.action)
    lines = [t("app.banner", version=__version__)]
    try:
        if action == "create":
            canary = store.add(note=args.note, decoy=str(args.decoy) if args.decoy else "")
            if args.decoy is not None:
                plant(args.decoy, canary.token)
            _note_event(env, "canary_create", {"id": canary.id})
            lines.append(t("canary.created", id=canary.id))
            if args.decoy is not None:
                lines.append(t("canary.planted", path=safe_text(str(args.decoy))))
            else:
                lines.append(t("canary.token", token=canary.token))
            lines.append(t("canary.hint"))
        elif action == "remove":
            if not args.id:
                lines.append(t("canary.need_id"))
                out.write("\n".join(lines) + "\n")
                return EXIT_USAGE
            removed = store.remove(args.id)
            if removed is None:
                lines.append(t("canary.unknown", id=safe_text(args.id, 40)))
                out.write("\n".join(lines) + "\n")
                return EXIT_USAGE
            _note_event(env, "canary_remove", {"id": removed.id})
            lines.append(t("canary.removed", id=removed.id))
        else:
            canaries = store.all()
            if not canaries:
                lines.append(t("canary.empty"))
            for canary in canaries:
                lines.append(
                    t(
                        "canary.row",
                        id=canary.id,
                        created=safe_text(canary.created[:19], 40),
                        note=safe_text(canary.note, 60) or "-",
                        where=safe_text(canary.decoy, 200) or "-",
                    )
                )
    except CanaryError as exc:
        lines.append(t("canary.failed", error=safe_text(str(exc), 200)))
        out.write("\n".join(lines) + "\n")
        return EXIT_INCOMPLETE
    out.write("\n".join(lines) + "\n")
    return EXIT_OK


def run_backup(args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO) -> int:
    action = BACKUP_ALIASES.get(args.action, args.action)
    lines = [t("app.banner", version=__version__)]
    try:
        if action == "create":
            archive = backup.create(env.data_dir, keep=args.keep)
            _note_event(env, "backup_create", {"file": safe_text(archive.name, 120)})
            lines.append(t("backup.created", path=safe_text(str(archive))))
            lines.append(t("backup.hint"))
        elif action == "extract":
            if not args.archive or not args.folder:
                lines.append(t("backup.need_args"))
                out.write("\n".join(lines) + "\n")
                return EXIT_USAGE
            restored = backup.extract(Path(args.archive), Path(args.folder))
            lines.append(
                t("backup.extracted", count=len(restored), path=safe_text(str(args.folder)))
            )
        else:
            found = backup.listing(env.data_dir)
            if not found:
                lines.append(t("backup.empty"))
            for path in found:
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                lines.append(t("backup.row", name=safe_text(path.name, 120), size=size))
    except backup.BackupError as exc:
        lines.append(t("backup.failed", error=safe_text(str(exc), 200)))
        out.write("\n".join(lines) + "\n")
        return EXIT_INCOMPLETE
    out.write("\n".join(lines) + "\n")
    return EXIT_OK


def _report_stderr(line: str) -> None:
    stream = sys.stderr
    if stream is None:
        return
    with contextlib.suppress(OSError, ValueError):
        stream.write(f"{SHIELD_PREFIX} {line}\n")
        stream.flush()


def _load_canaries(env: HostEnvironment, t: Translator) -> frozenset[str]:
    try:
        return CanaryStore(env.data_dir).tokens()
    except CanaryError as exc:
        _report_stderr(t("shield.canary_unreadable", error=safe_text(str(exc), 200)))
        return frozenset()


def run_shield_command(
    args: argparse.Namespace, t: Translator, command: list[str], env: HostEnvironment
) -> int:
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    if not command:
        _report_stderr(t("shield.no_command"))
        return EXIT_USAGE
    options = ShieldOptions(server=args.server or default_name(command), command=tuple(command))
    home = home_text(str(env.home))
    ledger = Ledger(env.data_dir) if args.ledger else None
    inspector = RulesInspector(
        server=safe_text(options.server, 80),
        policy=PolicyWatcher(env.data_dir, home).current,
        home=home,
        ledger=ledger,
        t=t,
        report=_report_stderr,
        pins=PinStore(env.data_dir, None, ledger),
        confirm=WindowConfirmer(),
        canaries=_load_canaries(env, t),
    )
    _report_stderr(inspector.describe())
    return run_shield(
        options,
        t=t,
        client_in=sys.stdin.buffer,
        client_out=sys.stdout.buffer,
        report=_report_stderr,
        ledger=ledger,
        inspector=inspector,
    )


def run_shield_rules(
    args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO
) -> int:
    action = RULE_ACTIONS[args.action]
    ws = shield_commands.Workspace(t, env.data_dir, home_text(str(env.home)), out)
    if action == "verify":
        return shield_commands.verify(ws, args.file)
    if action == "approve":
        return shield_commands.approve(ws)
    if action == "example":
        return shield_commands.example(ws, args.save)
    if action == "status":
        return shield_commands.status(ws)
    simulation = shield_commands.Simulation(
        server=args.test_server,
        phase=args.phase,
        method=args.method,
        tool=args.tool,
        arguments=args.arguments,
        text=args.text,
    )
    return shield_commands.simulate(ws, args.file, simulation)


def run_shield_tools(
    args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO
) -> int:
    action = TOOL_ACTIONS[args.action]
    ws = shield_commands.Workspace(t, env.data_dir, home_text(str(env.home)), out)
    store = PinStore(env.data_dir, None, Ledger(env.data_dir))
    server = args.tools_server or args.server
    if action == "list":
        return shield_commands.tools_list(ws, store)
    if action == "approve":
        return shield_commands.tools_approve(ws, store, server, args.tool_names)
    return shield_commands.tools_forget(ws, store, server)


def run_shield_confirm() -> int:
    from guardia.app.confirm import show_confirmation

    try:
        request = parse_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    except RequestError:
        return EXIT_USAGE
    try:
        answer = show_confirmation(request)
    except ImportError:
        return EXIT_INCOMPLETE
    if answer not in (Answer.ALLOW, Answer.ALLOW_REMEMBER, Answer.BLOCK, Answer.TIMEOUT):
        answer = Answer.BLOCK
    sys.stdout.buffer.write(answer_json(answer))
    sys.stdout.buffer.flush()
    return EXIT_OK


def run_shield_setup(
    args: argparse.Namespace, t: Translator, env: HostEnvironment, out: TextIO
) -> int:
    ws = shield_commands.Workspace(t, env.data_dir, home_text(str(env.home)), out)
    store = ActivationStore(env.data_dir, Ledger(env.data_dir))
    action = args.shield_command
    inventory = discover(env, DiscoveryOptions(skills=False))
    found = candidates(inventory)
    failed = inventory.failed_sources
    if action in ("list", "elenco"):
        return shield_commands.shield_list(ws, found, failed)
    selection = (args.setup_servers, args.setup_all, args.setup_confirm)
    if action in ("disable", "disattiva"):
        return shield_commands.shield_disable(ws, found, store, selection, failed)
    if action in ("relink", "ricollega"):
        return shield_commands.shield_relink(ws, found, store, selection, failed)
    return shield_commands.shield_enable(ws, found, selection, store, failed)


def dispatch_shield(
    args: argparse.Namespace,
    t: Translator,
    command: list[str],
    env: HostEnvironment,
    out: TextIO,
) -> int:
    if getattr(args, "shield_command", None) in SETUP_COMMANDS:
        return run_shield_setup(args, t, env, out)
    if getattr(args, "shield_command", None) in ("tools", "strumenti"):
        return run_shield_tools(args, t, env, out)
    if getattr(args, "shield_command", None):
        return run_shield_rules(args, t, env, out)
    return run_shield_command(args, t, command, env)


def split_command(arguments: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in arguments:
        return arguments, []
    split = arguments.index("--")
    if not any(argument in SHIELD_COMMANDS for argument in arguments[:split]):
        return arguments, []
    return arguments[:split], arguments[split + 1 :]


def main(
    argv: Sequence[str] | None = None,
    *,
    env: HostEnvironment | None = None,
    stdout: TextIO | None = None,
) -> int:
    arguments, command = split_command(list(sys.argv[1:] if argv is None else argv))
    if arguments[:2] in (["scudo", "conferma"], ["shield", "confirm"]):
        return run_shield_confirm()
    try:
        return _run(arguments, command, env, stdout)
    except Exception as exc:
        _report_crash(exc, arguments)
        return EXIT_INCOMPLETE


def _report_crash(exc: Exception, arguments: list[str]) -> None:
    stream = sys.stderr
    if stream is None:
        return
    t = Translator(detect_language(peek_language(arguments)))
    with contextlib.suppress(OSError, ValueError):
        traceback.print_exception(exc, file=stream)
        stream.write(t("cli.crash", error=safe_text(type(exc).__name__, 80)) + "\n")
        stream.flush()


def default_name(command: Sequence[str]) -> str:
    program = PurePath(command[0].replace("\\", "/")).stem
    if program.lower() not in PACKAGE_RUNNERS:
        return program or command[0]
    for part in command[1:]:
        if part.startswith("-") or part in RUNNER_WORDS:
            continue
        package = part.split("==", 1)[0]
        cut = package.find("@", 1)
        package = package if cut == -1 else package[:cut]
        return PurePath(package.replace("\\", "/")).name or program
    return program


def _run(
    arguments: list[str],
    command: list[str],
    env: HostEnvironment | None,
    stdout: TextIO | None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    _prepare_stream(out)
    t = Translator(detect_language(peek_language(arguments)))
    parser = build_parser(t)
    args = parser.parse_args(arguments)
    if args.command is None:
        parser.print_help(out)
        return EXIT_OK
    if args.command in RULES_COMMANDS:
        return run_rules(args, t, out)
    if args.command in SHIELD_COMMANDS:
        return dispatch_shield(args, t, command, env or HostEnvironment.from_os(), out)
    missing = _missing_paths(args)
    if missing:
        out.write(t("cli.missing_path", path=str(missing[0])) + "\n")
        return EXIT_USAGE
    environment = env or HostEnvironment.from_os()
    handlers = (
        (INVENTORY_COMMANDS, run_inventory),
        (SCAN_COMMANDS, run_scan),
        (LEDGER_COMMANDS, run_ledger),
        (CANARY_COMMANDS, run_canary),
        (BACKUP_COMMANDS, run_backup),
    )
    for names, handler in handlers:
        if args.command in names:
            return handler(args, t, environment, out)
    return EXIT_USAGE
