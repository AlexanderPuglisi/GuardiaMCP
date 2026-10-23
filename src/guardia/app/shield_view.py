from __future__ import annotations

from typing import Any

from guardia.display import safe_text
from guardia.i18n import Translator
from guardia.inventory import DiscoveryOptions, HostEnvironment, discover
from guardia.ledger import Ledger
from guardia.secure_store import Protector
from guardia.shield.activation import (
    ActivationStore,
    Candidate,
    Outcome,
    Support,
    candidates,
    manual_snippet,
)
from guardia.shield.pins import PinError, PinStore
from guardia.shield.policy import PolicyState, load_policy, rules_path
from guardia.shield.wrapping import launcher

SHIELD_EVENTS = frozenset(
    {
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
    }
)
MAX_EVENTS = 30
SCANNED_RECORDS = 2000
MANUAL = frozenset({Support.MANUAL_COMMENTS, Support.MANUAL_TOML})


def _home(env: HostEnvironment) -> str:
    return str(env.home).replace("\\", "/").rstrip("/").lower()


def server_candidates(env: HostEnvironment) -> list[Candidate]:
    return candidates(discover(env, DiscoveryOptions(skills=False)))


def _rules(env: HostEnvironment, t: Translator, protector: Protector | None) -> dict[str, Any]:
    policy = load_policy(env.data_dir, _home(env), protector)
    file = rules_path(env.data_dir)
    base = {"path": safe_text(str(file)), "exists": file.exists()}
    if policy.state is PolicyState.LOCKED and policy.reason is not None:
        reason = t(f"shield.locked_{policy.reason.value}")
        return base | {"state": "locked", "text": t("shield.state_locked", reason=reason)}
    if policy.ruleset is not None:
        text = t(
            "shield.state_active",
            count=len(policy.ruleset.rules),
            default=t(f"shield_rules.action_{policy.ruleset.default.value}"),
        )
        return base | {"state": "active", "text": text}
    return base | {"state": "none", "text": t("shield.state_none")}


def _server(candidate: Candidate, t: Translator, recorded: set[tuple[str, str]]) -> dict[str, Any]:
    server = candidate.server
    snippet = manual_snippet(server, launcher()) if candidate.support in MANUAL else ""
    return {
        "key": safe_text(server.key),
        "name": safe_text(server.name, 80),
        "client": t(f"client.{server.source.client.value}"),
        "path": safe_text(str(server.source.path)),
        "support": candidate.support.value,
        "status": t(f"shield_setup.support_{candidate.support.value}"),
        "can_enable": candidate.support is Support.AUTO,
        "can_disable": candidate.support is Support.PROTECTED
        and (server.name, str(server.source.path)) in recorded,
        "snippet": safe_text(snippet, 4000),
    }


def _event(record: dict[str, Any], t: Translator) -> dict[str, Any]:
    event = str(record.get("event", ""))
    raw = record.get("data")
    data: dict[str, Any] = raw if isinstance(raw, dict) else {}
    parts = [str(data.get("server", "") or data.get("file", ""))]
    if event == "shield_decision":
        action = str(data.get("action", ""))
        parts.append(t(f"shield_rules.action_{action}") if action else "")
        parts.append(str(data.get("tool") or data.get("method") or ""))
        if data.get("answer"):
            parts.append(t(f"shield.answer_{data['answer']}"))
    elif isinstance(data.get("tools"), list):
        names = [
            str(item.get("name", item)) if isinstance(item, dict) else str(item)
            for item in data["tools"]
        ]
        parts.append(", ".join(names[:8]))
    elif isinstance(data.get("servers"), list):
        parts.append(", ".join(str(item) for item in data["servers"][:8]))
    return {
        "seq": record.get("seq"),
        "time": safe_text(str(record.get("time", "")), 40),
        "event": event,
        "label": t(f"ui.event_{event}"),
        "details": safe_text(" · ".join(part for part in parts if part), 240),
    }


def _events(
    env: HostEnvironment, t: Translator, protector: Protector | None
) -> list[dict[str, Any]]:
    records = list(Ledger(env.data_dir, protector).records())[-SCANNED_RECORDS:]
    chosen = [r for r in records if r.get("event") in SHIELD_EVENTS][-MAX_EVENTS:]
    return [_event(record, t) for record in reversed(chosen)]


def _pending(env: HostEnvironment, t: Translator, protector: Protector | None) -> dict[str, Any]:
    try:
        waiting, _, valid = PinStore(env.data_dir, protector).pending()
    except (OSError, PinError):
        return {"valid": False, "items": []}
    items = [
        {
            "server": safe_text(item.server, 80),
            "tool": safe_text(item.name, 120),
            "reason": t(f"shield_rules.reason_{item.reason.value}"),
            "seen": safe_text(item.seen, 40),
            "fingerprint": item.fingerprint[:12],
        }
        for item in waiting
    ]
    return {"valid": valid, "items": items}


def shield_state(
    env: HostEnvironment,
    t: Translator,
    protector: Protector | None = None,
    found: list[Candidate] | None = None,
) -> dict[str, Any]:
    servers = found if found is not None else server_candidates(env)
    recorded = {
        (str(r.get("server")), str(r.get("file"))) for r in ActivationStore(env.data_dir).records()
    }
    listed = [_server(c, t, recorded) for c in servers]
    return {
        "rules": _rules(env, t, protector),
        "servers": listed,
        "protected": sum(1 for s in listed if s["support"] == Support.PROTECTED.value),
        "pending": _pending(env, t, protector),
        "events": _events(env, t, protector),
    }


def outcome_lines(report_changes: list[Any], t: Translator) -> list[str]:
    return [
        t(
            f"shield_setup.outcome_{change.outcome.value}",
            name=safe_text(change.server, 80),
            path=safe_text(str(change.file)),
        )
        for change in report_changes
    ]


def succeeded(report_changes: list[Any]) -> bool:
    return bool(report_changes) and all(c.outcome is Outcome.DONE for c in report_changes)
