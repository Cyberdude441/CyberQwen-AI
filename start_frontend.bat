@echo off
title CyberQwen-AI Frontend Interface (Vite + React)
echo ==============================================================================
echo CYBERQWEN-AI: STARTING FRONTEND WEB INTERFACE (React + Vite + Tailwind)
echo ==============================================================================
echo [*] UI URL: http://localhost:5173
echo ==============================================================================
cd /d "%~dp0frontend"

call npm run dev
pause
