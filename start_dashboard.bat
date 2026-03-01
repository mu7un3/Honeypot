@echo off
title Honeypot Web Dashboard (Next.js)
echo ============================================================
echo  HONEYPOT WEB DASHBOARD
echo ============================================================
echo.

REM Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Install from https://nodejs.org
    pause
    exit /b 1
)

cd /d "%~dp0honeypot-analytics"

REM Install dependencies if needed
if not exist "node_modules" (
    echo [*] Installing Node.js dependencies...
    npm install
)

echo [*] Starting web dashboard at http://localhost:3000
echo [*] Press Ctrl+C to stop
echo.
npm run dev
pause
