from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _variable(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value) if value and Path(value).is_absolute() else None


@dataclass(frozen=True, slots=True)
class HostEnvironment:
    platform: str
    home: Path
    app_config: Path
    local_app_data: Path
    managed_dir: Path
    cwd: Path
    data_dir: Path
    codex_home: Path | None = None
    claude_config_dir: Path | None = None

    @classmethod
    def from_os(cls) -> HostEnvironment:
        home = Path.home()
        cwd = Path.cwd()
        homes = {
            "codex_home": _variable("CODEX_HOME"),
            "claude_config_dir": _variable("CLAUDE_CONFIG_DIR"),
        }
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
                **homes,
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
                **homes,
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
            **homes,
        )

    def claude_dirs(self) -> list[Path]:
        dirs = [self.home / ".claude"]
        if self.claude_config_dir is not None and self.claude_config_dir != dirs[0]:
            dirs.append(self.claude_config_dir)
        return dirs

    def claude_state_files(self) -> list[Path]:
        files = [self.home / ".claude.json"]
        if self.claude_config_dir is not None:
            files.append(self.claude_config_dir / ".claude.json")
        return files

    def codex_dirs(self) -> list[Path]:
        dirs = [self.home / ".codex"]
        if self.codex_home is not None and self.codex_home != dirs[0]:
            dirs.append(self.codex_home)
        return dirs

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
