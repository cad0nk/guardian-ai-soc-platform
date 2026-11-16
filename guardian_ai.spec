# -*- mode: python ; coding: utf-8 -*-
# guardian_ai — PyInstaller spec (Windows, one-file, windowed)
#   Build:  pyinstaller guardian_ai.spec --noconfirm --clean
# Entry point is the single-file application module; source .py is NOT removed.
# Run from the repository root (build_windows.bat does this for you).
import os

ENTRY = "guardian_ai_v4_fixed.py"
ICON = os.path.join("assets", "icons", "guardian_ai.ico")

# Read-only assets are bundled (resolved at runtime via resource_path / sys._MEIPASS).
# NOTE: .env and soc_history.db are deliberately NOT bundled — API keys must never
# ship inside an exe, and the DB must live next to the exe (see app_base_dir()).
datas = [("assets", "assets")]

hiddenimports = [
    "ui", "ui.styles", "ui.styles.colors", "ui.styles.typography",
    "ui.styles.theme", "ui.styles.components", "ui.styles.qss_compat",
    "ui.widgets", "ui.icons",
    # python-whois / pyshark / numpy are optional at runtime (the app degrades gracefully);
    # they are listed so the executable includes them when present in the build environment.
    "whois", "dotenv", "reportlab", "pyshark", "numpy",
]

a = Analysis(
    [ENTRY],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "pytestqt"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="guardian_ai",
    icon=ICON,
    debug=False,
    strip=False,
    upx=False,          # UPX can corrupt Qt DLLs / trigger AV false positives
    console=False,      # --windowed
    disable_windowed_traceback=False,
)
