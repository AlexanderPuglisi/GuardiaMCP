from __future__ import annotations

from pathlib import Path

import pytest

from guardia.app.api import GuardiaApi, GuardiaUiError
from guardia.app.settings import SettingsStore
from guardia.inventory import HostEnvironment
from guardia.ledger import Ledger
from guardia.secure_store import RAW_PROTECTOR


def make_api(env: HostEnvironment, folder: Path | None = None) -> GuardiaApi:
    return GuardiaApi(
        env,
        SettingsStore(env.data_dir),
        folder_dialog=lambda: str(folder) if folder else None,
        protector=RAW_PROTECTOR,
    )


def events(env: HostEnvironment) -> list[str]:
    return [str(r["event"]) for r in Ledger(env.data_dir, RAW_PROTECTOR).records()]


def test_every_change_is_noted_with_before_and_after(env: HostEnvironment, tmp_path: Path) -> None:
    api = make_api(env, tmp_path)
    api.set_option("skills", False)
    api.set_option("skills", False)
    api.set_language("en")
    api.add_project()
    api.remove_project(str(tmp_path))
    items = api.settings_history()["items"]
    assert [item["setting"] for item in items] == [
        "Project folders",
        "Project folders",
        "Language",
        "Analyze skills",
    ]
    assert items[0]["change"] == f"removed {tmp_path}"
    assert items[1]["change"] == f"added {tmp_path}"
    assert items[2]["change"] == "Italiano → English"
    assert items[3]["change"] == "on → off"
    assert [item["can_restore"] for item in items] == [True, False, True, True]
    assert events(env).count("settings_changed") == 4
    ledger = api.ledger(10)
    assert any(e["label"] == "Setting changed" for e in ledger["events"])


def test_restore_puts_the_previous_value_back(env: HostEnvironment, tmp_path: Path) -> None:
    api = make_api(env, tmp_path)
    api.set_option("baseline", False)
    api.add_project()
    api.remove_project(str(tmp_path))
    items = api.settings_history()["items"]
    removed, added, baseline = items
    with pytest.raises(GuardiaUiError):
        api.restore_setting(baseline["seq"], False)
    state = api.restore_setting(baseline["seq"], True)
    assert state["settings"]["baseline"] is True
    with pytest.raises(GuardiaUiError):
        api.restore_setting(baseline["seq"], True)
    state = api.restore_setting(removed["seq"], True)
    assert state["settings"]["projects"] == [str(tmp_path)]
    state = api.restore_setting(added["seq"], True)
    assert state["settings"]["projects"] == []
    assert SettingsStore(env.data_dir).load().baseline is True
    for bad in (None, "1", True, 10_000):
        with pytest.raises(GuardiaUiError):
            api.restore_setting(bad, True)


def test_only_settings_events_can_be_restored(env: HostEnvironment) -> None:
    api = make_api(env)
    record = Ledger(env.data_dir, RAW_PROTECTOR).append("scan", {"setting": "skills"})
    with pytest.raises(GuardiaUiError):
        api.restore_setting(record["seq"], True)
    forged = Ledger(env.data_dir, RAW_PROTECTOR).append(
        "settings_changed", {"setting": "language", "before": "xx", "after": "it"}
    )
    with pytest.raises(GuardiaUiError):
        api.restore_setting(forged["seq"], True)
    assert SettingsStore(env.data_dir).load().language == "it"
