from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from guardia import __version__
from guardia.analysis import AnalysisOptions, analyze
from guardia.display import safe_text
from guardia.i18n import SUPPORTED_LANGUAGES, Translator, detect_language
from guardia.inventory import DiscoveryOptions, HostEnvironment
from guardia.ledger import Ledger, Verification
from guardia.model import Severity
from guardia.render.html import render_html
from guardia.render.rules_guide import render_rule_detail, render_rules_list, render_rules_markdown
from guardia.render.sarif import build_sarif
from guardia.render.terminal import render_inventory, render_scan, severity_label
from guardia.scanner import RULES, ScanReport
from guardia.shield import commands as shield_commands
from guardia.shield.inspector import RulesInspector
from guardia.shield.patterns import home_text
from guardia.shield.pins import PinStore
from guardia.shield.policy import PolicyWatcher
from guardia.shield.runner import ShieldOptions, run_shield

INVENTORY_COMMANDS = frozenset({"inventory", "inventario"})
SCAN_COMMANDS = frozenset({"scan", "scansiona"})
LEDGER_COMMANDS = frozenset({"ledger", "registro"})
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
LANG_FLAGS = ("--lang", "--lingua")
FAIL_LEVELS = ("info", "low", "medium", "high", "critical", "never")
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3


def peek_language(argv: Sequence[str]) -> str | None:
    for index, arg in enumerate(argv):
        for flag in LANG_FLAGS:
            if arg == flag and index + 1 < len(argv):
                return argv[index + 1]
            if arg.startswith(flag + "="):
                return arg.split("=", 1)[1]
    return None


def _language_options(t: Translator) -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--lang",
        "--lingua",
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
        "-o", "--output", "--salva", dest="output", type=Path, help=t("cli.output")
    )
    options.add_argument(
        "-p",
        "--project",
        "--progetto",
        dest="projects",
        action="append",
        type=Path,
        default=[],
        help=t("cli.project"),
    )
    options.add_argument(
        "--no-auto-projects",
        "--senza-progetti-automatici",
        dest="auto_projects",
        action="store_false",
        help=t("cli.no_auto_projects"),
    )
    options.add_argument(
        "--path",
        "--percorso",
        dest="paths",
        action="append",
        type=Path,
        default=[],
        help=t("cli.path"),
    )
    options.add_argument(
        "--no-skills",
        "--senza-skill",
        dest="skills",
        action="store_false",
        help=t("cli.no_skills"),
    )
    options.add_argument(
        "--no-tools",
        "--senza-strumenti",
        dest="tools",
        action="store_false",
        help=t("cli.no_tools"),
    )
    return options


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
        "--all-sources",
        "--tutte-le-fonti",
        dest="all_sources",
        action="store_true",
        help=t("cli.all_sources"),
    )
    scan = commands.add_parser(
        "scan", aliases=["scansiona"], help=t("cli.scan"), parents=[language, discovery]
    )
    scan.add_argument(
        "--fail-on",
        "--fallisci-da",
        dest="fail_on",
        choices=FAIL_LEVELS,
        default="high",
        help=t("cli.fail_on"),
    )
    scan.add_argument(
        "--no-baseline",
        "--senza-base",
        dest="baseline",
        action="store_false",
        help=t("cli.no_baseline"),
    )
    scan.add_argument(
        "--accept-changes",
        "--accetta-modifiche",
        dest="accept_changes",
        action="store_true",
        help=t("cli.accept_changes"),
    )
    scan.add_argument(
        "--format",
        "--formato",
        dest="format",
        choices=FORMATS,
        default="text",
        help=t("cli.format"),
    )
    scan.add_argument(
        "--no-ledger",
        "--senza-registro",
        dest="ledger",
        action="store_false",
        help=t("cli.no_ledger"),
    )
    ledger = commands.add_parser(
        "ledger", aliases=["registro"], help=t("cli.ledger"), parents=[language]
    )
    ledger.add_argument("action", choices=LEDGER_ACTIONS, help=t("cli.ledger_action"))
    ledger.add_argument("--last", "--ultimi", dest="last", type=int, default=10, help=t("cli.last"))
    ledger.add_argument("--anchor", "--ancora", dest="anchor", help=t("cli.anchor"))
    shield = commands.add_parser(
        "shield", aliases=["scudo"], help=t("shield.cli_help"), parents=[language]
    )
    shield.add_argument("--server", "--nome", dest="server", help=t("shield.cli_server"))
    shield.add_argument(
        "--no-ledger",
        "--senza-registro",
        dest="ledger",
        action="store_false",
        help=t("shield.cli_no_ledger"),
    )
    shield_commands_parser = shield.add_subparsers(dest="shield_command")
    shield_rules = shield_commands_parser.add_parser(
        "rules", aliases=["regole"], help=t("shield_rules.cli_help"), parents=[language]
    )
    shield_rules.add_argument(
        "action", choices=sorted(RULE_ACTIONS), help=t("shield_rules.cli_action")
    )
    shield_rules.add_argument("--file", type=Path, help=t("shield_rules.cli_file"))
    shield_rules.add_argument(
        "--server", dest="test_server", default="server", help=t("shield_rules.cli_server")
    )
    shield_rules.add_argument(
        "--fase", "--phase", dest="phase", default="call", help=t("shield_rules.cli_phase")
    )
    shield_rules.add_argument(
        "--metodo", "--method", dest="method", help=t("shield_rules.cli_method")
    )
    shield_rules.add_argument(
        "--strumento", "--tool", dest="tool", default="", help=t("shield_rules.cli_tool")
    )
    shield_rules.add_argument(
        "--argomenti", "--arguments", dest="arguments", help=t("shield_rules.cli_arguments")
    )
    shield_rules.add_argument(
        "--testo", "--text", dest="text", default="", help=t("shield_rules.cli_text")
    )
    shield_rules.add_argument(
        "--salva", "--save", dest="save", action="store_true", help=t("shield_rules.cli_save")
    )
    shield_tools = shield_commands_parser.add_parser(
        "tools", aliases=["strumenti"], help=t("shield_rules.tools_help"), parents=[language]
    )
    shield_tools.add_argument(
        "action", choices=sorted(TOOL_ACTIONS), help=t("shield_rules.tools_action")
    )
    shield_tools.add_argument("--server", dest="tools_server", help=t("shield_rules.tools_server"))
    shield_tools.add_argument(
        "--strumento",
        "--tool",
        dest="tool_names",
        action="append",
        default=[],
        help=t("shield_rules.tools_tool"),
    )
    rules = commands.add_parser(
        "rules", aliases=["regole"], help=t("guide.cli_help"), parents=[language]
    )
    rules.add_argument("rule", nargs="?", help=t("guide.cli_rule"))
    rules.add_argument("--markdown", action="store_true", help=t("guide.cli_markdown"))
    rules.add_argument("-o", "--output", "--salva", dest="output", type=Path, help=t("cli.output"))
    return parser


def _prepare_stream(stream: TextIO) -> None:
    if isinstance(stream, io.TextIOWrapper):
        stream.reconfigure(errors="backslashreplace")


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


def _emit(text: str, args: argparse.Namespace, t: Translator, out: TextIO) -> None:
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
        out.write(t("inventory.saved", path=str(args.output)) + "\n")
    else:
        out.write(text)


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
    _emit(text, args, t, out)
    return EXIT_OK


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
    _emit(render_report(report, output_format, t, env.cwd), args, t, out)
    return scan_exit_code(report, args.fail_on)


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
        records = list(ledger.records())[-max(args.last, 0) :] if args.last else []
        for record in records:
            data = record.get("data", {})
            summary = data.get("summary", {}) if isinstance(data, dict) else {}
            details = " · ".join(
                f"{severity_label(Severity[name.upper()], t)} {summary.get(name, 0)}"
                for name in ("critical", "high", "medium", "low")
            )
            lines.append(
                t(
                    "ledger.show_line",
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
    _emit(text, args, t, out)
    return EXIT_OK


def _report_stderr(line: str) -> None:
    stream = sys.stderr
    if stream is None:
        return
    with contextlib.suppress(OSError, ValueError):
        stream.write(f"{SHIELD_PREFIX} {line}\n")
        stream.flush()


def run_shield_command(
    args: argparse.Namespace, t: Translator, command: list[str], env: HostEnvironment
) -> int:
    if isinstance(sys.stderr, io.TextIOWrapper):
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    if not command:
        _report_stderr(t("shield.no_command"))
        return EXIT_USAGE
    options = ShieldOptions(
        server=args.server or Path(command[0]).stem or command[0], command=tuple(command)
    )
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
    if action == "list":
        return shield_commands.tools_list(ws, store)
    if action == "approve":
        return shield_commands.tools_approve(ws, store, args.tools_server, args.tool_names)
    return shield_commands.tools_forget(ws, store, args.tools_server)


def dispatch_shield(
    args: argparse.Namespace,
    t: Translator,
    command: list[str],
    env: HostEnvironment,
    out: TextIO,
) -> int:
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
    )
    for names, handler in handlers:
        if args.command in names:
            return handler(args, t, environment, out)
    return EXIT_USAGE
