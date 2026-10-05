@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
if not errorlevel 1 goto launch_py
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
if not errorlevel 1 goto launch_python
echo Installa Python 3.10 o successivo e abilita il launcher py o il comando python nel PATH.
pause
exit /b 1

:launch_py
py -3 app.py %*
goto finished

:launch_python
python app.py %*

:finished
if not errorlevel 1 exit /b 0
echo Avvio non riuscito. Leggere il messaggio precedente.
pause
exit /b 1
