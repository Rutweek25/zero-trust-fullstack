# Zero Trust Monitoring System - Complete Startup
# Runs: Backend + Frontend + Agent + USB Monitoring + Location Tracking

param(
    [switch]$NoAgent = $false,
    [switch]$NoFrontend = $false,
    [switch]$Help = $false
)

if ($Help) {
    Write-Host "USAGE: .\RUN_ALL.ps1 [options]"
    Write-Host ""
    Write-Host "OPTIONS:"
    Write-Host "  -NoAgent      Skip agent startup"
    Write-Host "  -NoFrontend   Skip frontend startup"
    Write-Host "  -Help         Show this help"
    Write-Host ""
    Write-Host "SERVICES: Backend + Frontend + Agent + DB Watcher"
    exit 0
}

$root = Get-Location
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Zero Trust Monitoring System" -ForegroundColor Cyan
Write-Host "Full Stack Startup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# BACKEND
Write-Host "[1/4] Starting Backend Server (FastAPI)..." -ForegroundColor Green
$backendCmd = "cd '$root\backend'; python -m uvicorn app:app --reload --port 8000 --host 127.0.0.1"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd
Start-Sleep -Seconds 2

# FRONTEND
if (-not $NoFrontend) {
    Write-Host "[2/4] Starting Frontend Server (Vite)..." -ForegroundColor Blue
    $frontendCmd = "cd '$root\frontend'; npm run dev -- --host 127.0.0.1 --port 5173"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd
    Start-Sleep -Seconds 2
} else {
    Write-Host "[2/4] Skipping Frontend" -ForegroundColor Yellow
}

# AGENT
if (-not $NoAgent) {
    Write-Host "[3/4] Starting Agent (USB + Location Monitoring)..." -ForegroundColor Magenta
    $agentCmd = "cd '$root\agent'; .\run_agent.bat"
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $agentCmd
    Start-Sleep -Seconds 2
} else {
    Write-Host "[3/4] Skipping Agent" -ForegroundColor Yellow
}

# DB WATCHER
Write-Host "[4/4] Starting Database Watcher..." -ForegroundColor Magenta
$watcherCmd = "cd '$root\backend'; python check_db.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $watcherCmd
Start-Sleep -Seconds 1

# COMPLETE
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "All Services Started!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "SERVICES:" -ForegroundColor Yellow
if (-not $NoFrontend) {
    Write-Host "  Frontend:     http://localhost:5173" -ForegroundColor Blue
}
Write-Host "  Backend:      http://localhost:8000" -ForegroundColor Green
Write-Host "  API Docs:     http://localhost:8000/docs" -ForegroundColor Green
if (-not $NoAgent) {
    Write-Host "  Agent:        Running (USB/Location monitoring)" -ForegroundColor Magenta
}
Write-Host "  DB Watcher:   Monitoring telemetry in real-time" -ForegroundColor Magenta
Write-Host ""

Write-Host "QUICK TEST:" -ForegroundColor Yellow
Write-Host "  1. Login: http://localhost:5173/login" -ForegroundColor Blue
Write-Host "     User: superadmin@company.com" -ForegroundColor Blue
Write-Host "     Pass: super@1234" -ForegroundColor Blue
Write-Host "  2. Insert a USB device" -ForegroundColor Magenta
Write-Host "  3. Check DB Watcher terminal for USB detection" -ForegroundColor Magenta
Write-Host ""

Write-Host "FEATURES:" -ForegroundColor Yellow
Write-Host "  - USB device tracking (< 2 seconds)" -ForegroundColor Green
Write-Host "  - Geolocation tracking" -ForegroundColor Green
Write-Host "  - Real-time telemetry" -ForegroundColor Green
Write-Host "  - Device approval workflow" -ForegroundColor Green
Write-Host ""

Write-Host "Close terminal windows individually to stop services" -ForegroundColor Cyan
Write-Host ""
