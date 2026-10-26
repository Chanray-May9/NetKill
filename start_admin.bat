@echo off
setlocal
cd /d "%~dp0"

rem Launch WITH UAC elevation (needed to actually cut the target off).
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
if not exist "%~dp0.venv\Scripts\pythonw.exe" goto NOVENV
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0gui.py"
exit /b 0

:NOVENV
echo [ERROR] .venv not found. Run install.bat first.
echo Path: %~dp0.venv
pause
exit /b 1
