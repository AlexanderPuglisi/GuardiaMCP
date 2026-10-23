from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

import PyInstaller.__main__

from guardia import __version__

PROJECT = Path(__file__).resolve().parent.parent
SPEC = PROJECT / "packaging" / "guardia.spec"
DIST = PROJECT / "dist"
WORK = PROJECT / "build"
FOLDER = DIST / "GuardiaMCP"
ARCHIVE = DIST / f"GuardiaMCP-{__version__}-windows-x64.zip"
EXTRA_FILES = ("LICENSE", "NOTICE", "README.md", "SECURITY.md", "AUDIT.md")
GUIDES = ("SCUDO.md", "SHIELD.md", "REGOLE.md", "RULES.md", "IMPARA-MCP.md")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def package() -> None:
    for name in EXTRA_FILES:
        shutil.copy2(PROJECT / name, FOLDER / name)
    (FOLDER / "docs").mkdir(exist_ok=True)
    for name in GUIDES:
        shutil.copy2(PROJECT / "docs" / name, FOLDER / "docs" / name)
    with zipfile.ZipFile(ARCHIVE, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(FOLDER.rglob("*")):
            if path.is_file():
                archive.write(path, Path("GuardiaMCP") / path.relative_to(FOLDER))
    lines = [f"{sha256(ARCHIVE)}  {ARCHIVE.name}"]
    lines += [
        f"{sha256(FOLDER / name)}  GuardiaMCP/{name}" for name in ("guardia.exe", "GuardiaMCP.exe")
    ]
    (DIST / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    PyInstaller.__main__.run(
        [
            "--noconfirm",
            "--clean",
            "--log-level=WARN",
            f"--distpath={DIST}",
            f"--workpath={WORK}",
            str(SPEC),
        ]
    )
    package()
    print(ARCHIVE)
    print((DIST / "SHA256SUMS.txt").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
