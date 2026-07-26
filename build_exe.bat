@echo off
setlocal
cd /d "%~dp0"
py -3 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt
pyinstaller --noconfirm --clean --onefile --windowed --name AnonSurfSafe AnonSurfSafe.py
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo.
echo Built: dist\AnonSurfSafe.exe
pause
