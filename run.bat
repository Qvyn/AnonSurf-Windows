@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import PySide6" >nul 2>&1
if errorlevel 1 (
  echo Installing the Qt 6 interface...
  py -3 -m pip install -r requirements.txt
  if errorlevel 1 (
    echo.
    echo Failed to install the Qt 6 interface.
    pause
    exit /b 1
  )
)
py -3 AnonSurfSafe.py
if errorlevel 1 (
  echo.
  echo Failed to start. Install Python 3.11 or newer from https://www.python.org/downloads/windows/
  pause
)
