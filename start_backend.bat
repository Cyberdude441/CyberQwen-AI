@echo off
title CyberQwen-AI Backend API (FastAPI)
echo ==============================================================================
echo CYBERQWEN-AI: STARTING BACKEND REST API SERVER (FastAPI + Uvicorn)
echo ==============================================================================
echo [*] Working Directory: %~dp0
echo [*] API URL:           http://localhost:8000
echo [*] Interactive Docs:  http://localhost:8000/docs
echo ==============================================================================
cd /d "%~dp0"

if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)

python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
pause
