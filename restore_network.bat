@echo off
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
