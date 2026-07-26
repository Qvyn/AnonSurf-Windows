@echo off
setlocal
cd /d "%~dp0"
py -3 AnonSurfSafe.py --restore-proxy
if errorlevel 1 (
  echo Exact restore failed or Python is unavailable.
  echo Disabling the current-user manual proxy as an emergency fallback...
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
)
pause
