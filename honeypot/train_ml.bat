@echo off
title Honeypot ML Training
echo ============================================================
echo  HONEYPOT ML TRAINING
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM Install dependencies
echo [*] Installing Python dependencies...
pip install scikit-learn numpy 2>&1

REM Copy .env if not exists
if not exist "%~dp0.env" (
    echo [*] Creating .env from example...
    copy "%~dp0.env.example" "%~dp0.env"
    echo [!] Edit honeypot\.env with your email credentials before running.
)

REM Train models
echo.
echo [*] Training ML models on synthetic data...
cd /d "%~dp0"
set PYTHONPATH=%~dp0
python ml\ml_pipeline.py train data\honeypot_synthetic.json

echo.
echo [*] Training complete. Models saved to models\
pause
