@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo NESS - Integrated Cyber Lab / Simple Windows Build
echo ============================================================
echo No WSL. No VMware. No VirtualBox. No Docker. No Npcap.
echo The training network, services, traffic and topology are built
echo and managed directly by NESS using Python and local sockets.
echo ============================================================
echo.

if not exist ".env" copy ".env.example" ".env" >nul

if not exist ".venv\Scripts\python.exe" (
    echo [NESS] Creating local Python environment...
    python -m venv ".venv"
    if errorlevel 1 (
        echo Python was not found. Install 64-bit Python and enable Add Python to PATH.
        pause
        exit /b 1
    )
)

".venv\Scripts\python.exe" -c "import flask, flask_sock, dotenv, requests, reportlab, serial, werkzeug" >nul 2>&1
if errorlevel 1 (
    echo [NESS] Installing required Python packages. This happens only when packages are missing...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto :pipfail
) else (
    echo [OK] Python packages are already installed. No download needed.
)

".venv\Scripts\python.exe" scripts\project_self_check.py
if errorlevel 1 (
    echo.
    echo NESS self-check found an application problem. Review the messages above.
    pause
    exit /b 1
)

echo.
echo NESS will start at http://127.0.0.1:5000
echo After login open: Cyber Range - Network Topology
echo The integrated lab starts automatically by default.
echo Keep this window open while using NESS.
echo.
".venv\Scripts\python.exe" app.py
pause
exit /b 0

:pipfail
echo Python dependency installation failed.
pause
exit /b 1
