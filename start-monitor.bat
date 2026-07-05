@echo off
rem ---------------------------------------------------------------------
rem DICOM Network Monitor launcher (right-click, "Run as administrator")
rem
rem Packet capture on Windows needs Administrator rights: Npcap only
rem shows network adapters to elevated processes by default. This script
rem warns if it is not elevated but still starts the app, which will
rem show the same warning in the browser.
rem
rem First run: creates a local .venv and installs the dependencies.
rem Every run: starts the web app, then opens the browser at the UI.
rem Close this window (or Ctrl+C) to stop the monitor.
rem ---------------------------------------------------------------------
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo  *** NOT RUNNING AS ADMINISTRATOR ***
    echo  Packet capture needs elevation. Close this window, then
    echo  right-click start-monitor.bat and choose "Run as administrator".
    echo  Continuing anyway so you can read the same message in the browser...
    echo.
)

where py >nul 2>nul
if errorlevel 1 (
    echo Python launcher 'py' not found. Install Python 3 from python.org
    echo and check "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3 -m venv .venv || (pause & exit /b 1)
    echo Installing dependencies...
    ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || (pause & exit /b 1)
)

echo Starting DICOM Network Monitor on http://127.0.0.1:8090 ...
start "" http://127.0.0.1:8090
".venv\Scripts\python.exe" main.py
pause
