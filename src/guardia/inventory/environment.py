from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class HostEnvironment:
    platform: str
    home: Path
    app_config: Path
    local_app_data: Path
    managed_dir: Path
    cwd: Path
    data_dir: Path

    @classmethod
    def from_os(cls) -> HostEnvironment:
        home = Path.home()
        cwd = Path.cwd()
        if sys.platform == "win32":
            local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
            return cls(
                platform="windows",
                home=home,
                app_config=Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming"),
                local_app_data=local,
                managed_dir=Path(os.environ.get("PROGRAMFILES") or r"C:\Program Files")
                / "ClaudeCode",
                cwd=cwd,
                data_dir=local / "GuardiaMCP",
            )
        if sys.platform == "darwin":
            support = home / "Library" / "Application Support"
            return cls(
                platform="macos",
                home=home,
                app_config=support,
                local_app_data=support,
                managed_dir=Path("/Library/Application Support/ClaudeCode"),
                cwd=cwd,
                data_dir=support / "GuardiaMCP",
            )
        config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
        data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
        return cls(
            platform="linux",
            home=home,
            app_config=config,
            local_app_data=config,
            managed_dir=Path("/etc/claude-code"),
            cwd=cwd,
            data_dir=data / "guardia-mcp",
        )

    @classmethod
    def for_root(cls, root: Path, platform: str = "windows") -> HostEnvironment:
        home = root / "home"
        return cls(
            platform=platform,
            home=home,
            app_config=home / "AppData" / "Roaming",
            local_app_data=home / "AppData" / "Local",
            managed_dir=root / "ProgramFiles" / "ClaudeCode",
            cwd=root / "cwd",
            data_dir=root / "data",
        )
