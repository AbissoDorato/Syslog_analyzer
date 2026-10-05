@echo off
cd /d "%~dp0"
python app.py
if errorlevel 1 (
  echo.
  echo Impossibile avviare il parser. Verifica che Python 3 sia installato e disponibile nel PATH.
  pause
)
