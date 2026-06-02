@echo off
REM ============================================================
REM  FirmwareGuard — one-click Windows build script
REM  Double-click this file, or run it from cmd / PowerShell.
REM ============================================================

echo.
echo  FirmwareGuard Builder
echo  =====================
echo.

REM Change to the directory containing this batch file
cd /d "%~dp0"

REM Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found on PATH.
    echo         Download from https://python.org/downloads
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version

REM Install / upgrade PyInstaller
echo.
echo [INFO] Installing PyInstaller...
pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)

REM Run the build
echo.
echo [INFO] Starting build...
echo.
python build_exe.py
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See errors above.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build complete!
echo  Your EXE is in the dist\ folder.
echo ============================================================
echo.
pause
