from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

from guardia import __version__

PACKAGING = Path(SPECPATH)
PROJECT = PACKAGING.parent
ICON = str(PROJECT / "src" / "guardia" / "app" / "guardia.ico")
NUMBERS = tuple(int(part) for part in __version__.split(".")[:3]) + (0,)
EXCLUDES = ["tkinter", "unittest", "pydoc", "doctest", "lib2to3", "PIL", "PyInstaller"]


def version_info(description, internal_name):
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=NUMBERS, prodvers=NUMBERS),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "Alexander Puglisi"),
                            StringStruct("FileDescription", description),
                            StringStruct("FileVersion", __version__),
                            StringStruct("InternalName", internal_name),
                            StringStruct("LegalCopyright", "Apache-2.0 - by Alexander Puglisi"),
                            StringStruct("OriginalFilename", internal_name + ".exe"),
                            StringStruct("ProductName", "Guardia MCP"),
                            StringStruct("ProductVersion", __version__),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )


def analysis(script):
    return Analysis(
        [str(PACKAGING / script)],
        pathex=[str(PROJECT / "src")],
        datas=collect_data_files("guardia"),
        excludes=EXCLUDES,
        noarchive=False,
    )


cli = analysis("guardia_cli.py")
app = analysis("guardia_app.py")

cli_exe = EXE(
    PYZ(cli.pure),
    cli.scripts,
    [],
    exclude_binaries=True,
    name="guardia",
    console=True,
    icon=ICON,
    version=version_info("Guardia MCP command line", "guardia"),
    upx=False,
)
app_exe = EXE(
    PYZ(app.pure),
    app.scripts,
    [],
    exclude_binaries=True,
    name="GuardiaMCP",
    console=False,
    icon=ICON,
    version=version_info("Guardia MCP desktop app", "GuardiaMCP"),
    upx=False,
)
COLLECT(
    cli_exe,
    cli.binaries,
    cli.datas,
    app_exe,
    app.binaries,
    app.datas,
    name="GuardiaMCP",
    upx=False,
)
