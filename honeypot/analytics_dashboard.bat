@echo off
title Honeypot Analytics Dashboard
echo ============================================================
echo  HONEYPOT ANALYTICS DASHBOARD
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

cd /d "%~dp0"
set PYTHONPATH=%~dp0
python analytics.py
pause
