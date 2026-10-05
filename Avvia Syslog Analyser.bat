@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 app.py
) else (
  python app.py
)
if errorlevel 1 (
  echo.
  echo Avvio non riuscito. Installa Python 3.10 o successivo e assicurati che sia disponibile nel PATH.
  pause
)
