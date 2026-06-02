"""
build_exe.py — FirmwareGuard Windows EXE builder
Run this on a Windows machine with Python 3.10+ installed.

Usage:
    pip install pyinstaller
    python build_exe.py

Output: dist\FirmwareGuard.exe        (standalone, no install needed)
        dist\FirmwareGuard_Setup.exe  (installer wizard, only if NSIS is installed)
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
#  Resolve paths robustly — works regardless of CWD or how the script
#  was invoked (double-click, cmd, PowerShell, py launcher).
# ---------------------------------------------------------------------------
ROOT = Path(os.path.abspath(__file__)).parent   # folder containing build_exe.py
SRC  = ROOT / "src"
DIST = ROOT / "dist"
BUILD = ROOT / "build"
ICON = ROOT / "assets" / "shield.ico"

APP_NAME    = "FirmwareGuard"
APP_VERSION = "1.1.0"

# The entry-point script — resolved to an absolute Windows path string,
# never passed through Path.__str__ which can produce forward slashes.
ENTRY = str(SRC / "main.py")


# ---------------------------------------------------------------------------
def check_deps():
    """Verify PyInstaller is available."""
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("[ERROR] PyInstaller not found.")
        print("        Run:  pip install pyinstaller")
        sys.exit(1)

    if not (SRC / "main.py").exists():
        print(f"[ERROR] Cannot find src\\main.py")
        print(f"        Expected location: {SRC / 'main.py'}")
        print(f"        Make sure you are running build_exe.py from the")
        print(f"        firmware_analyzer folder, not from inside src\\")
        sys.exit(1)

    print(f"[OK] Entry point : {ENTRY}")
    print(f"[OK] Source dir  : {SRC}")
    print(f"[OK] Output dir  : {DIST}")


# ---------------------------------------------------------------------------
def build():
    print(f"\n{'='*60}")
    print(f"  Building {APP_NAME} v{APP_VERSION}")
    print(f"{'='*60}\n")

    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    # --add-data separator:  ; on Windows,  : on macOS/Linux
    sep = ";" if sys.platform == "win32" else ":"

    # Collect every .py file in src individually so PyInstaller
    # can find them even if glob expansion differs between shells.
    src_files = list(SRC.glob("*.py"))
    add_data_args = []
    for f in src_files:
        add_data_args += ["--add-data", f"{f}{sep}."]

    args = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name",       APP_NAME,
        "--distpath",   str(DIST),
        "--workpath",   str(BUILD),
        "--specpath",   str(BUILD),
        "--clean",
        "--noconfirm",
        # Ensure all src modules are on the import path inside the bundle
        "--paths",      str(SRC),
        # Hidden imports — tkinter sub-modules are not auto-detected
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "tkinter.font",
        "--hidden-import", "analyzer",
        "--hidden-import", "report",
        "--hidden-import", "knowledge",
    ] + add_data_args

    # Icon
    if ICON.exists():
        args += ["--icon", str(ICON)]
    else:
        print(f"[WARN] Icon not found at {ICON} — building without icon")

    # Windows version metadata
    vf = _write_version_file()
    if vf and sys.platform == "win32":
        args += ["--version-file", vf]

    # Entry point — MUST be last argument
    args.append(ENTRY)

    print("PyInstaller command:")
    for a in args:
        print(f"  {a}")
    print()

    result = subprocess.run(args, cwd=str(ROOT))

    if result.returncode != 0:
        print("\n[ERROR] Build failed — see output above.")
        sys.exit(1)

    exe = DIST / f"{APP_NAME}.exe"
    if not exe.exists():
        # PyInstaller sometimes omits .exe on non-Windows — check both
        exe_nox = DIST / APP_NAME
        if exe_nox.exists():
            exe = exe_nox
        else:
            print(f"[ERROR] Expected output not found at {DIST}")
            sys.exit(1)

    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"\n[SUCCESS] {exe}")
    print(f"          Size: {size_mb:.1f} MB")
    _post_build(exe)


# ---------------------------------------------------------------------------
def _write_version_file():
    """Write a PyInstaller Windows version-info file."""
    vf = BUILD / "version_info.txt"
    vf.parent.mkdir(parents=True, exist_ok=True)
    major, minor, patch = APP_VERSION.split(".")
    content = (
        "VSVersionInfo(\n"
        "  ffi=FixedFileInfo(\n"
        f"    filevers=({major},{minor},{patch},0),\n"
        f"    prodvers=({major},{minor},{patch},0),\n"
        "    mask=0x3f, flags=0x0, OS=0x40004,\n"
        "    fileType=0x1, subtype=0x0, date=(0,0)\n"
        "  ),\n"
        "  kids=[\n"
        "    StringFileInfo([\n"
        "      StringTable('040904B0', [\n"
        f"        StringStruct('CompanyName',      'FirmwareGuard'),\n"
        f"        StringStruct('FileDescription',  'Firmware Security Analyzer'),\n"
        f"        StringStruct('FileVersion',      '{APP_VERSION}'),\n"
        f"        StringStruct('InternalName',     '{APP_NAME}'),\n"
        f"        StringStruct('LegalCopyright',   '2025 FirmwareGuard'),\n"
        f"        StringStruct('OriginalFilename', '{APP_NAME}.exe'),\n"
        f"        StringStruct('ProductName',      '{APP_NAME}'),\n"
        f"        StringStruct('ProductVersion',   '{APP_VERSION}'),\n"
        "      ])\n"
        "    ]),\n"
        "    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n"
        "  ]\n"
        ")\n"
    )
    vf.write_text(content, encoding="utf-8")
    return str(vf)


# ---------------------------------------------------------------------------
def _post_build(exe: Path):
    print(f"\n{'='*60}")
    print("  Post-build")
    print(f"{'='*60}")

    if shutil.which("makensis"):
        print("\n[INFO] NSIS detected — generating installer…")
        _build_nsis(exe)
    else:
        print("\n[INFO] NSIS not found — standalone EXE only.")
        print("       Get NSIS from https://nsis.sourceforge.io/ for a")
        print("       proper setup wizard with Start Menu shortcut + uninstaller.")
        print(f"\n  ✓  Standalone EXE ready:\n     {exe}\n")

    print("Done!")


# ---------------------------------------------------------------------------
def _build_nsis(exe: Path):
    nsi = (
        f'!define APP_NAME "{APP_NAME}"\n'
        f'!define APP_VERSION "{APP_VERSION}"\n'
        f'!define EXE_NAME "{APP_NAME}.exe"\n'
        '\n'
        f'Name "${{APP_NAME}} ${{APP_VERSION}}"\n'
        f'OutFile "{DIST}\\{APP_NAME}_Setup.exe"\n'
        'InstallDir "$PROGRAMFILES64\\${{APP_NAME}}"\n'
        'RequestExecutionLevel admin\n'
        'SetCompressor /SOLID lzma\n'
        '\n'
        'Page directory\n'
        'Page instfiles\n'
        '\n'
        'Section "Install"\n'
        '  SetOutPath $INSTDIR\n'
        f'  File "{exe}"\n'
        '  CreateShortCut "$DESKTOP\\${{APP_NAME}}.lnk" "$INSTDIR\\${{EXE_NAME}}"\n'
        '  CreateDirectory "$SMPROGRAMS\\${{APP_NAME}}"\n'
        '  CreateShortCut "$SMPROGRAMS\\${{APP_NAME}}\\${{APP_NAME}}.lnk" "$INSTDIR\\${{EXE_NAME}}"\n'
        '  CreateShortCut "$SMPROGRAMS\\${{APP_NAME}}\\Uninstall.lnk" "$INSTDIR\\Uninstall.exe"\n'
        '  WriteUninstaller "$INSTDIR\\Uninstall.exe"\n'
        '  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "DisplayName" "${{APP_NAME}}"\n'
        '  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "UninstallString" "$INSTDIR\\Uninstall.exe"\n'
        '  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "DisplayVersion" "${{APP_VERSION}}"\n'
        'SectionEnd\n'
        '\n'
        'Section "Uninstall"\n'
        '  Delete "$INSTDIR\\${{EXE_NAME}}"\n'
        '  Delete "$INSTDIR\\Uninstall.exe"\n'
        '  Delete "$DESKTOP\\${{APP_NAME}}.lnk"\n'
        '  RMDir /r "$SMPROGRAMS\\${{APP_NAME}}"\n'
        '  RMDir "$INSTDIR"\n'
        '  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}"\n'
        'SectionEnd\n'
    )
    nsi_path = BUILD / "installer.nsi"
    nsi_path.write_text(nsi, encoding="utf-8")
    result = subprocess.run(["makensis", str(nsi_path)], cwd=str(ROOT))
    if result.returncode == 0:
        print(f"[SUCCESS] Installer: {DIST / (APP_NAME + '_Setup.exe')}")
    else:
        print("[WARN] NSIS build failed — standalone EXE is still usable")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    check_deps()
    build()
