@echo off
title Honeypot - Active
echo ============================================================
echo  HONEYPOT SYSTEM
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM Check .env
if not exist "%~dp0.env" (
    echo [!] No .env file found. Copying from example...
    copy "%~dp0.env.example" "%~dp0.env"
    echo [!] Edit honeypot\.env with your email credentials.
    notepad "%~dp0.env"
    pause
)

REM Check models exist, train if not
if not exist "%~dp0models\classifier.pkl" (
    echo [*] ML models not found. Training now...
    call "%~dp0train_ml.bat"
)

echo [*] Starting honeypot on all ports...
echo [*] Press Ctrl+C to stop
echo.
cd /d "%~dp0"
set PYTHONPATH=%~dp0
python honeypot.py
pause
