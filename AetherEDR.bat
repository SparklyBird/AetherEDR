@echo off
rem ============================================================
rem  AetherEDR launcher (Windows). Double-click to start.
rem    first run : creates .venv, installs dependencies
rem    every run : asks for Administrator, starts the console
rem
rem  Options:
rem    AetherEDR.bat selftest     check this machine
rem    AetherEDR.bat demo         load DEMO-* sample data first
rem    AetherEDR.bat reinstall    reinstall dependencies
rem    AetherEDR.bat --no-admin   skip the Administrator prompt
rem    anything else is passed to run.py, e.g. --port 9000
rem
rem  The window closes by itself after a normal stop. After an error it stays open.
rem ============================================================
setlocal EnableExtensions
cd /d "%~dp0"
title AetherEDR

set "MODE=run"
set "ELEVATE=1"
set "REINSTALL="
set "DEMO="
set "EXTRA="
set "ORIGARGS=%*"

:parse
if "%~1"=="" goto :parsed
if /i "%~1"=="--no-admin" set "ELEVATE=0" & shift & goto :parse
if /i "%~1"=="selftest" set "MODE=selftest" & shift & goto :parse
if /i "%~1"=="reinstall" set "REINSTALL=1" & shift & goto :parse
if /i "%~1"=="demo" set "DEMO=1" & shift & goto :parse
set "EXTRA=%EXTRA% %~1"
shift
goto :parse
:parsed

rem ---- Administrator gives full memory visibility ----
fltmc >nul 2>&1
if not errorlevel 1 goto :elevated
if "%ELEVATE%"=="0" goto :elevated
echo Requesting Administrator rights for full memory visibility...
echo ^(use --no-admin to skip^)
if defined ORIGARGS (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%ORIGARGS%' -Verb RunAs" >nul 2>&1
) else (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
)
if errorlevel 1 (
  echo Elevation was declined. Continuing without it; memory visibility will be limited.
  echo.
  goto :elevated
)
exit /b 0

:elevated
rem ---- virtual environment ----
if exist ".venv\Scripts\python.exe" goto :have_venv
echo Creating virtual environment...
call :mkvenv
if errorlevel 1 goto :no_python
set "REINSTALL=1"

:have_venv
set "PY=%~dp0.venv\Scripts\python.exe"
if defined REINSTALL del ".venv\.deps-ok" >nul 2>&1
if exist ".venv\.deps-ok" goto :deps_ready

echo Installing dependencies. First run takes a minute or two...
"%PY%" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 goto :fail
"%PY%" -m pip install --disable-pip-version-check -q -r requirements-yara.txt >nul 2>&1
if errorlevel 1 (
  echo Note: YARA memory scanning is not installed. Everything else works.
  echo       It needs Python 3.12 or 3.13. See README.md, section "Optional: YARA".
)
echo ok> ".venv\.deps-ok"

:deps_ready
if "%MODE%"=="selftest" (
  "%PY%" -m edr.selftest
  goto :end
)
if defined DEMO (
  "%PY%" manage.py migrate -v0
  "%PY%" manage.py seed_demo
)
echo.
echo Starting AetherEDR. Use Exit in the console, or press Ctrl+C here, to stop.
"%PY%" run.py %EXTRA%
set "RC=%errorlevel%"
rem A normal stop (the Exit button or Ctrl+C) closes this window. An error keeps it open so the message can be read.
if "%RC%"=="0" (
  endlocal
  exit /b 0
)
goto :end

:mkvenv
rem Prefer 3.13 / 3.12: they have a prebuilt yara-python wheel.
for %%V in (3.13 3.12 3.11 3.10) do (
  py -%%V -c "import sys" >nul 2>&1
  if not errorlevel 1 (
    py -%%V -m venv .venv
    if not errorlevel 1 exit /b 0
  )
)
python -c "import sys" >nul 2>&1
if errorlevel 1 exit /b 1
python -m venv .venv
exit /b %errorlevel%

:no_python
echo.
echo Python 3.10 or newer was not found. Install it, then run this file again:
echo     winget install Python.Python.3.13
goto :end

:fail
echo.
echo Setup failed. Scroll up for the error. Try:  AetherEDR.bat reinstall

:end
echo.
pause
endlocal
