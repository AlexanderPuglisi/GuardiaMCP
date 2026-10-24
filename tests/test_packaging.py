from __future__ import annotations

import ast
import re
import struct
from pathlib import Path

PROJECT = Path(__file__).parent.parent
PACKAGING = PROJECT / "packaging"
MAX_GIF_BYTES = 2 * 1024 * 1024


def called_main(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    assert len(imports) == 1
    assert [alias.name for alias in imports[0].names] == ["main"]
    return imports[0].module or ""


def test_entry_points_match_the_installed_scripts() -> None:
    assert called_main(PACKAGING / "guardia_cli.py") == "guardia.cli"
    assert called_main(PACKAGING / "guardia_app.py") == "guardia.app.main"
    pyproject = (PROJECT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'guardia = "guardia.cli:main"' in pyproject
    assert 'guardia-app = "guardia.app.main:main"' in pyproject


def test_spec_builds_both_executables_with_resources() -> None:
    spec = (PACKAGING / "guardia.spec").read_text(encoding="utf-8")
    assert 'collect_data_files("guardia")' in spec
    assert 'name="guardia",\n    console=True' in spec
    assert 'name="GuardiaMCP",\n    console=False' in spec
    assert spec.count("upx=False") == 3
    assert "debug=True" not in spec


def test_both_programs_ship_a_dotnet_config_for_downloaded_zips() -> None:
    config = (PACKAGING / "dotnet.exe.config").read_text(encoding="utf-8")
    assert '<loadFromRemoteSources enabled="true"/>' in config
    assert config.index("<runtime>") < config.index("loadFromRemoteSources")
    build = (PROJECT / "scripts" / "build_exe.py").read_text(encoding="utf-8")
    assert 'PROGRAMS = ("guardia.exe", "GuardiaMCP.exe")' in build
    assert 'shutil.copy2(DOTNET_CONFIG, FOLDER / f"{program}.config")' in build


def test_zip_carries_every_file_the_readme_links_to() -> None:
    build = (PROJECT / "scripts" / "build_exe.py").read_text(encoding="utf-8")
    shipped = {*ast.literal_eval(build.split("EXTRA_FILES = ", 1)[1].split(")", 1)[0] + ")")}
    guides = ast.literal_eval(build.split("GUIDES = ", 1)[1].split(")", 1)[0] + ")")
    shipped |= {f"docs/{name}" for name in guides}
    readme = (PROJECT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(((?!https?:)[^)#]+)\)|src=\"([^\"]+)\"", readme):
        link = next(part for part in target if part)
        assert link in shipped, link
    spec = (PACKAGING / "guardia.spec").read_text(encoding="utf-8")
    for module in ("cryptography", "setuptools", "pkg_resources"):
        assert f'"{module}"' in spec


def test_icon_contains_small_and_large_sizes() -> None:
    data = (PROJECT / "src" / "guardia" / "app" / "guardia.ico").read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data)
    assert (reserved, kind) == (0, 1)
    sizes = {data[6 + 16 * index] or 256 for index in range(count)}
    assert {16, 32, 48, 256} <= sizes


def test_demo_gifs_are_published_and_small() -> None:
    for language in ("it", "en"):
        path = PROJECT / "docs" / f"demo-{language}.gif"
        data = path.read_bytes()
        assert data[:6] == b"GIF89a"
        assert len(data) < MAX_GIF_BYTES
