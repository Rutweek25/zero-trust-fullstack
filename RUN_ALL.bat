@echo off
REM ============================================================================
REM Zero Trust Monitoring System - Complete Startup (Windows Batch)
REM Runs: Backend + Frontend + Agent + USB Monitoring + Location Tracking
REM ============================================================================

setlocal enabledelayedexpansion

if "%1"=="/help" goto show_help
if "%1"=="/?" goto show_help

echo.
echo ====================================
echo Zero Trust Monitoring System
echo Complete Startup (All Services)
echo ====================================
echo.

cd /d "%~dp0"
set ROOT_DIR=%cd%

REM ============================================================================
REM BACKEND STARTUP
REM ============================================================================
echo [1/4] Starting Backend Server (FastAPI on port 8000)...
start "Zero Trust - Backend" cmd /k "cd /d "%ROOT_DIR%\backend" && python -m uvicorn app:app --reload --port 8000 --host 127.0.0.1"
timeout /t 2 /nobreak >nul

REM ============================================================================
REM FRONTEND STARTUP
REM ============================================================================
echo [2/4] Starting Frontend Server (Vite on port 5173)...
start "Zero Trust - Frontend" cmd /k "cd /d "%ROOT_DIR%\frontend" && npm run dev -- --host 127.0.0.1 --port 5173"
timeout /t 2 /nobreak >nul

REM ============================================================================
REM AGENT STARTUP
REM ============================================================================
echo [3/4] Starting Agent (USB + Location Monitoring)...
start "Zero Trust - Agent" cmd /k "cd /d "%ROOT_DIR%\agent" && run_agent.bat"
timeout /t 2 /nobreak >nul

REM ============================================================================
REM DATABASE WATCHER
REM ============================================================================
echo [4/4] Starting Database Watcher (Real-time USB Telemetry)...
start "Zero Trust - DB Watcher" cmd /k "cd /d "%ROOT_DIR%\backend" && python check_db.py"
timeout /t 1 /nobreak >nul

REM ============================================================================
REM INFORMATION
REM ============================================================================
cls
echo.
echo ====================================
echo ^! All Services Started
echo ====================================
echo.
echo SERVICES:
echo   ^> Frontend:     http://localhost:5173
echo   ^> Backend:      http://localhost:8000
echo   ^> API Docs:     http://localhost:8000/docs
echo   ^> Agent:        Running (USB/Location monitoring)
echo   ^> DB Watcher:   Monitoring telemetry in real-time
echo.
echo QUICK TEST:
echo   1. Login: http://localhost:5173/login
echo      User: superadmin@company.com
echo      Pass: super@1234
echo   2. Insert a USB device
echo   3. Check DB Watcher terminal for real-time USB detection
echo.
echo FEATURES ENABLED:
echo   - USB device tracking and detection
echo   - Geolocation tracking (browser location)
echo   - Real-time telemetry monitoring
echo   - Device approval workflow
echo   - Session-device binding
echo   - Risk scoring and trust levels
echo.
echo WINDOWS: 4 terminals opened with services
echo CLOSE: Each terminal window individually to stop services
echo.
timeout /t 10 /nobreak >nul
goto :eof

:show_help
echo.
echo Zero Trust Monitoring System - Complete Startup
echo.
echo USAGE: RUN_ALL.bat
echo.
echo This script starts all services:
echo   1. Backend (FastAPI on port 8000)
echo   2. Frontend (Vite on port 5173)
echo   3. Agent (USB and Location Monitoring)
echo   4. Database Watcher (Real-time Telemetry)
echo.
echo REQUIREMENTS:
echo   - Python 3.9+
echo   - Node.js 16+
echo   - Virtual environments already set up
echo.
echo FEATURES:
echo   - USB device detection and tracking
echo   - Geolocation tracking from browser
echo   - Device approval workflow
echo   - Session monitoring with location
echo   - Real-time telemetry database
echo.
pause >nul
goto :eof

:eof
