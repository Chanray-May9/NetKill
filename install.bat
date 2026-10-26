@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   NetKill setup  (scapy + Npcap check)
echo ==========================================
echo.

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python not found. Install Python 3.9+ and enable "Add to PATH".
    pause
    exit /b 1
)
for /f "delims=" %%v in ('%PY% --version 2^>^&1') do echo [INFO] %%v

if not exist ".venv\Scripts\python.exe" (
    echo [1/2] creating venv .venv ...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] venv creation failed.
        pause
        exit /b 1
    )
)

echo [2/2] installing scapy ...
".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -U pip scapy
if errorlevel 1 (
    echo [WARN] default index failed, retrying Tsinghua mirror ...
    ".venv\Scripts\python.exe" -m pip install -q -i https://pypi.tuna.tsinghua.edu.cn/simple scapy
)

echo.
if exist "C:\Windows\System32\Npcap" (
    echo [OK] Npcap detected.
) else (
    echo [WARN] Npcap not found. scapy needs Npcap to send ARP packets on Windows.
    echo        Download: https://npcap.com/dist/npcap-1.79.exe
    echo        During setup check "Install Npcap in WinPcap API-compatible Mode".
)

echo.
echo Done. Double-click start_gui.bat to launch.
pause
