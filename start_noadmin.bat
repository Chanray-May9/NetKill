@echo off
setlocal
cd /d "%~dp0"

rem Launch WITHOUT UAC (scan only / Npcap allows user mode).
if not exist "%~dp0.venv\Scripts\pythonw.exe" goto NOVENV
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0gui.py"
exit /b 0

:NOVENV
echo [ERROR] .venv not found. Run install.bat first.
echo Path: %~dp0.venv
pause
exit /b 1
