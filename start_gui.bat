@echo off
setlocal
cd /d "%~dp0"

rem Default: launch AS ADMIN (UAC prompt, click Yes).
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs } catch { exit 1 }"
    if errorlevel 1 (
        echo [WARN] UAC was cancelled. Launching without admin...
        goto NOADMIN
    )
    exit /b
)
if not exist "%~dp0.venv\Scripts\pythonw.exe" goto NOVENV
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0gui.py"
exit /b 0

:NOADMIN
if not exist "%~dp0.venv\Scripts\pythonw.exe" goto NOVENV
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0gui.py"
exit /b 0

:NOVENV
echo [ERROR] .venv not found. Run install.bat first.
echo Path: %~dp0.venv
pause
exit /b 1
