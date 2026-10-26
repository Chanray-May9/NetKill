# -*- coding: utf-8 -*-
"""生成纯 ASCII 的 .bat 启动器（避免中文 Windows cmd 的 GBK 乱码拆行问题）"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

START_GUI = r"""@echo off
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
"""

START_NOADMIN = r"""@echo off
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
"""

START_ADMIN = r"""@echo off
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
"""

INSTALL = r"""@echo off
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
"""

RESTORE = r"""@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   Emergency restore: flush ARP + restart WLAN
echo ==========================================
net session >nul 2>&1
if not "%errorlevel%"=="0" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
echo [1/3] flushing ARP cache ...
arp -d *
echo [2/3] restarting WLAN adapter ...
netsh interface set interface "WLAN" admin=disable >nul 2>&1
timeout /t 2 /nobreak >nul
netsh interface set interface "WLAN" admin=enable >nul 2>&1
echo [3/3] flushing DNS ...
ipconfig /flushdns >nul 2>&1
echo.
echo Done. If still broken: reconnect Wi-Fi or reboot router.
pause
"""


def write_ascii_bat(name: str, content: str) -> None:
    path = os.path.join(HERE, name)
    data = content.replace("\n", "\r\n").encode("ascii")
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {name} ({len(data)} bytes, ASCII, CRLF)")


if __name__ == "__main__":
    write_ascii_bat("start_gui.bat", START_GUI)
    write_ascii_bat("start_noadmin.bat", START_NOADMIN)
    write_ascii_bat("start_admin.bat", START_ADMIN)
    write_ascii_bat("install.bat", INSTALL)
    write_ascii_bat("restore_network.bat", RESTORE)
