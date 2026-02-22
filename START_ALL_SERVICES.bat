@echo off
REM ============================================================================
REM Zero Trust Monitoring System - One-Click Launcher
REM Simply double-click this file to start everything
REM ============================================================================

setlocal enabledelayedexpansion

REM Get the directory where this script is located
cd /d "%~dp0"

REM Check if RUN_ALL.bat exists
if exist RUN_ALL.bat (
    echo Starting Zero Trust Monitoring System...
    call RUN_ALL.bat
) else (
    echo ERROR: RUN_ALL.bat not found!
    echo Please ensure you are in the correct directory.
    pause >nul
    exit /b 1
)
