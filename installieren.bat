@echo off
setlocal
cd /d "%~dp0"
echo Sigillum Arcanum - Installation
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if errorlevel 1 (
  echo Python 3.11 oder neuer fehlt. Bitte installieren: https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
if exist .venv rmdir /s /q .venv
py -3 -m venv .venv || goto fehler
rem 1. pip selbst auf eine gepruefte Version bringen (mit Pruefsumme)
.venv\Scripts\python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: --no-deps -r requirements-pip.txt || goto fehler
rem 2. Bibliotheken mit festen Versionen und Pruefsummen
.venv\Scripts\python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: --no-deps -r requirements-windows.txt || goto fehler
echo.
echo Fertig. Starten mit start.bat
pause
exit /b 0
:fehler
echo Installation fehlgeschlagen - nichts wurde gestartet.
pause
exit /b 1
