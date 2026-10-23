from __future__ import annotations

import json
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from guardia import __version__
from guardia.analysis import AnalysisOptions, analyze
from guardia.app.settings import (
    BOOLEAN_OPTIONS,
    MAX_PROJECTS,
    AppSettings,
    SettingsStore,
    validate_language,
    validate_project,
    with_option,
)
from guardia.app.shield_view import (
    outcome_lines,
    server_candidates,
    shield_state,
    succeeded,
)
from guardia.app.viewmodel import report_view, ui_strings
from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.inventory import DiscoveryOptions, HostEnvironment
from guardia.ledger import Ledger
from guardia.model import Severity, sha256_hex
from guardia.render.html import render_html
from guardia.render.sarif import build_sarif
from guardia.render.terminal import severity_label
from guardia.safeio import SafeReadError
from guardia.scanner import ScanReport
from guardia.secure_store import Protector
from guardia.shield.activation import ActivationStore, Support
from guardia.shield.pins import PinError, PinStore
from guardia.shield.policy import ApprovalError, approve_rules
from guardia.shield.wrapping import launcher

ANCHOR = re.compile(r"^\d{1,9}:[0-9a-f]{64}$")
EXPORT_FORMATS = {"html": ".html", "json": ".json", "sarif": ".sarif"}
MAX_LEDGER_EVENTS = 500
MAX_NAME = 200
WINDOW_EDGES = frozenset({"n", "s", "e", "w", "ne", "nw", "se", "sw"})
MAX_COORDINATE = 100_000
MIN_WINDOW_SIZE = 200
MAX_WINDOW_SIZE = 20_000

SaveDialog = Callable[[str], str | None]
FolderDialog = Callable[[], str | None]


class GuardiaUiError(Exception):
    pass


class WindowControls(Protocol):
    def minimize(self) -> None: ...

    def close(self) -> None: ...

    def place(self, x: int, y: int, width: int, height: int) -> None: ...

    def resize(self, width: int, height: int, edge: str) -> None: ...


def bounded(value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("not a number")
    if not math.isfinite(value) or not low <= value <= high:
        raise ValueError("out of range")
    return round(value)


def _no_save(_: str) -> str | None:
    return None


def _no_folder() -> str | None:
    return None


class GuardiaApi:
    def __init__(
        self,
        env: HostEnvironment,
        store: SettingsStore,
        *,
        save_dialog: SaveDialog = _no_save,
        folder_dialog: FolderDialog = _no_folder,
        protector: Protector | None = None,
        window: WindowControls | None = None,
    ) -> None:
        self._env = env
        self._store = store
        self._settings = store.load()
        self._report: ScanReport | None = None
        self._seconds = 0.0
        self._lock = threading.Lock()
        self._save_dialog = save_dialog
        self._folder_dialog = folder_dialog
        self._protector = protector
        self._window = window

    def _t(self) -> Translator:
        return Translator(self._settings.language)

    def _ledger(self) -> Ledger:
        return Ledger(self._env.data_dir, self._protector)

    def _options(self, accept: bool = False) -> AnalysisOptions:
        settings = self._settings
        return AnalysisOptions(
            discovery=DiscoveryOptions(
                project_dirs=tuple(Path(p) for p in settings.projects), skills=settings.skills
            ),
            tools=settings.tools,
            baseline=settings.baseline,
            accept_changes=accept,
            protector=self._protector,
        )

    def _save_settings(self, settings: AppSettings) -> None:
        self._settings = settings
        self._store.save(settings)

    def _fail(self, key: str) -> GuardiaUiError:
        return GuardiaUiError(self._t()(f"ui.error_{key}"))

    def _report_view(self) -> dict[str, Any] | None:
        if self._report is None:
            return None
        return report_view(self._report, self._t(), self._seconds)

    def _run(self, accept: bool) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise self._fail("busy")
        try:
            start = time.perf_counter()
            report = analyze(self._env, self._options(accept))
            self._seconds = time.perf_counter() - start
            self._report = report
        finally:
            self._lock.release()
        return report_view(report, self._t(), self._seconds)

    def state(self) -> dict[str, Any]:
        t = self._t()
        return {
            "version": __version__,
            "language": self._settings.language,
            "ui": ui_strings(t),
            "settings": self._settings.to_dict(),
            "data_dir": safe_text(str(self._env.data_dir)),
            "report": self._report_view(),
        }

    def scan(self) -> dict[str, Any]:
        return self._run(accept=False)

    def accept_changes(self, confirmed: object) -> dict[str, Any]:
        if confirmed is not True:
            raise self._fail("confirmation")
        return self._run(accept=True)

    def _event_view(self, record: dict[str, Any], t: Translator) -> dict[str, Any]:
        event = str(record.get("event", ""))
        raw = record.get("data")
        data: dict[str, Any] = raw if isinstance(raw, dict) else {}
        if event == "scan":
            raw_summary = data.get("summary")
            summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
            details = " · ".join(
                f"{severity_label(Severity[name.upper()], t)} {int(summary.get(name, 0) or 0)}"
                for name in ("critical", "high", "medium", "low")
            )
            if data.get("baseline") == "accepted":
                details += " · " + t("ui.event_accepted")
        elif event == "export":
            details = f"{str(data.get('format', '')).upper()} · {data.get('file', '')}"
        elif event == "shield_stop" and "forwarded" in data:
            details = t(
                "ui.event_shield_counts",
                server=data.get("server", ""),
                forwarded=int(data.get("forwarded", 0) or 0),
                blocked=int(data.get("blocked", 0) or 0),
                dropped=int(data.get("dropped", 0) or 0),
            )
        elif event in ("shield_start", "shield_stop"):
            details = str(data.get("server", ""))
        else:
            details = ""
        known = (
            "scan",
            "export",
            "shield_start",
            "shield_stop",
            "shield_decision",
            "shield_enabled",
            "shield_disabled",
            "tools_pinned",
            "tools_pending",
            "tools_approved",
            "tools_forgotten",
            "rules_approved",
        )
        label_key = f"ui.event_{event}" if event in known else "ui.event_other"
        return {
            "seq": record.get("seq"),
            "time": safe_text(str(record.get("time", "")), 40),
            "label": t(label_key),
            "details": safe_text(details, 200),
            "hash": safe_text(str(record.get("hash", "")), 64),
        }

    def ledger(self, limit: object = 20) -> dict[str, Any]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_LEDGER_EVENTS
        ):
            raise self._fail("invalid")
        return self._ledger_view(None, limit)

    def verify_anchor(self, anchor: object) -> dict[str, Any]:
        if not isinstance(anchor, str) or not ANCHOR.match(anchor.strip()):
            raise self._fail("anchor")
        return self._ledger_view(anchor.strip(), 20)

    def _ledger_view(self, anchor: str | None, limit: int) -> dict[str, Any]:
        t = self._t()
        ledger = self._ledger()
        verification = ledger.verify(anchor)
        records = list(ledger.records())[-limit:]
        return {
            "records": verification.records,
            "intact": verification.intact,
            "tampered": verification.tampered,
            "anchor": verification.anchor if verification.records else "",
            "anchor_checked": anchor is not None,
            "issues": [
                {
                    "line": issue.line,
                    "problem": t(f"ledger_problem.{issue.problem.value}"),
                }
                for issue in verification.issues
            ],
            "events": [self._event_view(record, t) for record in reversed(records)],
        }

    def export(self, output_format: object) -> dict[str, Any]:
        if not isinstance(output_format, str) or output_format not in EXPORT_FORMATS:
            raise self._fail("invalid")
        if self._report is None:
            raise self._fail("need_scan")
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        chosen = self._save_dialog(f"guardia-report-{stamp}{EXPORT_FORMATS[output_format]}")
        if not chosen:
            return {"saved": False}
        target = Path(chosen)
        t = self._t()
        if output_format == "html":
            content = render_html(self._report, t)
        elif output_format == "sarif":
            content = json.dumps(
                build_sarif(self._report, t, self._env.cwd), indent=2, ensure_ascii=True
            )
        else:
            content = json.dumps(self._report.to_dict(), indent=2, ensure_ascii=True)
        data = content.encode("utf-8")
        target.write_bytes(data)
        digest = sha256_hex(data)
        self._ledger().append(
            "export", {"format": output_format, "file": target.name, "sha256": digest}
        )
        return {"saved": True, "path": safe_text(str(target)), "sha256": digest}

    def set_language(self, language: object) -> dict[str, Any]:
        try:
            value = validate_language(language)
        except ValueError as exc:
            raise self._fail("invalid") from exc
        self._save_settings(replace(self._settings, language=value))
        return self.state()

    def set_option(self, name: object, value: object) -> dict[str, Any]:
        if not isinstance(name, str) or name not in BOOLEAN_OPTIONS or not isinstance(value, bool):
            raise self._fail("invalid")
        self._save_settings(with_option(self._settings, name, value))
        return self.state()

    def add_project(self) -> dict[str, Any]:
        if len(self._settings.projects) >= MAX_PROJECTS:
            raise self._fail("too_many")
        chosen = self._folder_dialog()
        if not chosen:
            return self.state()
        try:
            project = validate_project(chosen)
        except ValueError as exc:
            raise self._fail("invalid") from exc
        projects = tuple(dict.fromkeys([*self._settings.projects, project]))
        self._save_settings(replace(self._settings, projects=projects))
        return self.state()

    def remove_project(self, path: object) -> dict[str, Any]:
        if not isinstance(path, str) or path not in self._settings.projects:
            raise self._fail("invalid")
        projects = tuple(p for p in self._settings.projects if p != path)
        self._save_settings(replace(self._settings, projects=projects))
        return self.state()

    def _home(self) -> str:
        return str(self._env.home).replace("\\", "/").rstrip("/").lower()

    def _shield_result(self, message: str, ok: bool) -> dict[str, Any]:
        state = shield_state(self._env, self._t(), self._protector)
        state["message"] = message
        state["ok"] = ok
        return state

    def shield(self) -> dict[str, Any]:
        return shield_state(self._env, self._t(), self._protector)

    def shield_enable(self, key: object, confirmed: object) -> dict[str, Any]:
        if confirmed is not True:
            raise self._fail("confirmation")
        if not isinstance(key, str):
            raise self._fail("invalid")
        chosen = [
            c
            for c in server_candidates(self._env)
            if c.server.key == key and c.support is Support.AUTO
        ]
        if not chosen:
            raise self._fail("invalid")
        store = ActivationStore(self._env.data_dir, self._ledger())
        report = store.enable([chosen[0].server], launcher())
        lines = outcome_lines(report.changes, self._t())
        return self._shield_result("\n".join(lines), succeeded(report.changes))

    def shield_disable(self, name: object, confirmed: object) -> dict[str, Any]:
        if confirmed is not True:
            raise self._fail("confirmation")
        store = ActivationStore(self._env.data_dir, self._ledger())
        recorded = {str(r.get("server")) for r in store.records()}
        if not isinstance(name, str) or name not in recorded:
            raise self._fail("invalid")
        report = store.disable([name])
        lines = outcome_lines(report.changes, self._t())
        return self._shield_result("\n".join(lines), succeeded(report.changes))

    def shield_approve_tools(self, server: object, confirmed: object) -> dict[str, Any]:
        if confirmed is not True:
            raise self._fail("confirmation")
        if not isinstance(server, str) or not server or len(server) > MAX_NAME:
            raise self._fail("invalid")
        t = self._t()
        try:
            chosen = PinStore(self._env.data_dir, self._protector, self._ledger()).approve(server)
        except (OSError, PinError) as exc:
            message = t("shield_rules.tools_failed", error=safe_text(str(exc), 200))
            return self._shield_result(message, False)
        if not chosen:
            return self._shield_result(t("shield_rules.tools_nothing", server=server), False)
        tools = ", ".join(safe_text(item, 120) for item in chosen)
        return self._shield_result(
            t("shield_rules.tools_approved", server=server, tools=tools), True
        )

    def shield_approve_rules(self, confirmed: object) -> dict[str, Any]:
        if confirmed is not True:
            raise self._fail("confirmation")
        t = self._t()
        try:
            result, _ = approve_rules(self._env.data_dir, self._home(), self._protector)
        except SafeReadError:
            return self._shield_result(t("ui.shield_no_rules_file"), False)
        except ApprovalError as exc:
            message = t("shield_rules.approval_failed", error=safe_text(str(exc), 200))
            return self._shield_result(message, False)
        if result.ruleset is None:
            message = t("shield_rules.invalid", count=len(result.errors))
            return self._shield_result(message, False)
        message = t(
            "shield_rules.approved",
            count=len(result.ruleset.rules),
            sha=result.ruleset.sha256[:16],
        )
        return self._shield_result(message, True)

    def window_minimize(self) -> None:
        if self._window is not None:
            self._window.minimize()

    def window_close(self) -> None:
        if self._window is not None:
            self._window.close()

    def window_place(self, x: object, y: object, width: object, height: object) -> None:
        try:
            geometry = (
                bounded(x, -MAX_COORDINATE, MAX_COORDINATE),
                bounded(y, -MAX_COORDINATE, MAX_COORDINATE),
                bounded(width, MIN_WINDOW_SIZE, MAX_WINDOW_SIZE),
                bounded(height, MIN_WINDOW_SIZE, MAX_WINDOW_SIZE),
            )
        except ValueError as exc:
            raise self._fail("invalid") from exc
        if self._window is not None:
            self._window.place(*geometry)

    def window_resize(self, width: object, height: object, edge: object) -> None:
        if not isinstance(edge, str) or edge not in WINDOW_EDGES:
            raise self._fail("invalid")
        try:
            size = (
                bounded(width, MIN_WINDOW_SIZE, MAX_WINDOW_SIZE),
                bounded(height, MIN_WINDOW_SIZE, MAX_WINDOW_SIZE),
            )
        except ValueError as exc:
            raise self._fail("invalid") from exc
        if self._window is not None:
            self._window.resize(*size, edge)
