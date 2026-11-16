@echo off
REM ============================================================================
REM  guardian_ai - Windows build (PyInstaller, one-file, windowed)
REM  Run from the repository root:   build_windows.bat
REM  Requires: Python 3.12 on PATH (py -3.12 also works - see docs/INSTALLATION.md)
REM ============================================================================
setlocal
cd /d "%~dp0"

echo [1/5] Creating isolated build environment (.venv-build)...
if not exist .venv-build (
    python -m venv .venv-build || goto :fail
)
call .venv-build\Scripts\activate.bat || goto :fail

echo [2/5] Installing pinned build dependencies...
python -m pip install --upgrade pip || goto :fail
python -m pip install -r requirements-build.txt || goto :fail

echo [3/5] Regenerating icon assets...
python tools\generate_icons.py || goto :fail

echo [4/5] Building executable...
pyinstaller guardian_ai.spec --noconfirm --clean || goto :fail

echo [5/5] SHA-256 checksum (paste this into the release notes):
powershell -NoProfile -Command "Get-FileHash .\dist\guardian_ai.exe -Algorithm SHA256 | Format-List"

echo.
echo Build finished: dist\guardian_ai.exe
echo  - Put your own .env (API keys) NEXT TO the .exe. It is never bundled.
echo  - guardian_ai.exe is NOT code-signed; Windows SmartScreen may warn on first run.
echo  - PCAP analysis additionally needs Wireshark/TShark installed on the target PC.
exit /b 0

:fail
echo.
echo BUILD FAILED - see the messages above.
exit /b 1
