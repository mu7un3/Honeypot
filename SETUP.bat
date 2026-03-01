@echo off
title Honeypot Setup
echo ============================================================
echo  HONEYPOT SYSTEM - SETUP
echo  ML-Enhanced Honeypot + Analytics Dashboard
echo ============================================================
echo.

REM ── 1. Python check / auto-install via winget ──────────────────
echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Attempting auto-install via winget...
    winget --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] winget not found.
        echo         Please install Python 3.10+ manually from:
        echo         https://python.org/downloads
        echo         Make sure to check "Add Python to PATH" during install.
        pause
        exit /b 1
    )
    winget install --id Python.Python.3.11 -e --source winget --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo [ERROR] winget install failed.
        echo         Please install Python 3.10+ manually from https://python.org/downloads
        pause
        exit /b 1
    )
    echo [!] Python installed. Restarting PATH for this session...
    REM Refresh PATH so python is found immediately
    for /f "tokens=*" %%i in ('where python 2^>nul') do set "PYTHON_PATH=%%i"
    if "%PYTHON_PATH%"=="" (
        echo [!] Python not yet on PATH. Please close and re-run this script.
        pause
        exit /b 1
    )
)
python --version
echo [OK] Python found.
echo.

REM ── 2. Node.js check / auto-install via winget ─────────────────
echo [2/5] Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo [!] Node.js not found. Attempting auto-install via winget...
    winget --version >nul 2>&1
    if errorlevel 1 (
        echo [WARN] winget not found. Node.js web dashboard will not work.
        echo        Install Node.js LTS manually from https://nodejs.org
        goto :skip_node
    )
    winget install --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo [WARN] Node.js auto-install failed.
        echo        Install manually from https://nodejs.org (LTS version)
        echo        The terminal dashboard (analytics_dashboard.bat) will still work.
        goto :skip_node
    )
    echo [!] Node.js installed. You may need to reopen this window for PATH to refresh.
) else (
    node --version
    echo [OK] Node.js found.
)
:skip_node
echo.

REM ── 3. Python dependencies ─────────────────────────────────────
echo [3/5] Installing Python dependencies...
pip install scikit-learn numpy requests python-dotenv 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to install Python packages.
    echo         Try running this script as Administrator.
    pause
    exit /b 1
)
echo [OK] Python dependencies installed.
echo.

REM ── 4. Configure .env ──────────────────────────────────────────
echo [4/5] Configuring environment...
if not exist "%~dp0honeypot\.env" (
    if exist "%~dp0honeypot\.env.example" (
        copy "%~dp0honeypot\.env.example" "%~dp0honeypot\.env" >nul
        echo [!] Created honeypot\.env from template.
        echo [!] Opening .env for you to fill in your email credentials...
        notepad "%~dp0honeypot\.env"
    ) else (
        echo [WARN] .env.example not found. Create honeypot\.env manually.
    )
) else (
    echo [OK] .env already exists.
)
echo.

REM ── 5. Train ML models ─────────────────────────────────────────
echo [5/5] Training ML models (this may take a minute)...
cd /d "%~dp0honeypot"
set PYTHONPATH=%~dp0honeypot
python ml\ml_pipeline.py train data\honeypot_synthetic.json
if errorlevel 1 (
    echo [WARN] ML training failed. The honeypot will run without ML scoring.
    echo        Try running: python ml\ml_pipeline.py train data\honeypot_synthetic.json
)
echo.

REM ── Done ───────────────────────────────────────────────────────
echo ============================================================
echo  SETUP COMPLETE
echo ============================================================
echo.
echo  Next steps:
echo.
echo  1. Run the honeypot (as Administrator):
echo       honeypot\start_honeypot.bat
echo.
echo  2. View the web dashboard:
echo       start_dashboard.bat
echo       Then open http://localhost:3000
echo.
echo  3. View the terminal dashboard:
echo       honeypot\analytics_dashboard.bat
echo.
echo  NOTE: start_honeypot.bat must be run as Administrator to bind
echo        to privileged ports (SSH:22, HTTP:80, FTP:21, etc.)
echo.
echo  Optional: Add your AbuseIPDB API key to honeypot\.env for
echo            automatic threat reporting (ABUSEIPDB_API_KEY=...)
echo ============================================================
pause
