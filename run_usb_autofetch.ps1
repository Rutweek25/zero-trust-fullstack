# Zero Trust USB Auto-Fetch Launcher (Windows)
# Starts Backend + Frontend + Agent so USB insert/remove is sent automatically to admin portal

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonPath = "C:\Users\Dell\AppData\Local\Programs\Python\Python312\python.exe"

Write-Host "Starting Zero Trust stack with USB auto-fetch..." -ForegroundColor Cyan

if (-not (Test-Path $pythonPath)) {
    Write-Host "Python not found at: $pythonPath" -ForegroundColor Red
    Write-Host "Update run_usb_autofetch.ps1 with your python.exe path." -ForegroundColor Yellow
    exit 1
}

# Free ports if occupied
try {
    $backendConns = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
    if ($backendConns) {
        $backendPids = $backendConns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $backendPids) {
            if ($procId -and $procId -ne 0) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
        }
    }

    $frontendConns = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue
    if ($frontendConns) {
        $frontendPids = $frontendConns | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($procId in $frontendPids) {
            if ($procId -and $procId -ne 0) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
        }
    }
} catch {}

# Stop any previous agent runtime launched via python
try {
    $agentProcs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "agent.main" -or $_.CommandLine -match "import agent.main" }
    foreach ($proc in $agentProcs) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
} catch {}

# Start Backend (window closes when backend stops)
$backendCmd = "Set-Location '$root'; & '$pythonPath' -m uvicorn app:app --app-dir '$root\\backend' --host 127.0.0.1 --port 8000"
$backendProc = Start-Process powershell -ArgumentList "-Command", $backendCmd -WindowStyle Normal -PassThru

Start-Sleep -Seconds 2

# Start Frontend
$frontendCmd = "Set-Location '$root\\frontend'; npx vite --host 127.0.0.1 --port 5173"
$frontendProc = Start-Process powershell -ArgumentList "-Command", $frontendCmd -WindowStyle Normal -PassThru

Start-Sleep -Seconds 2

# Start Agent (integrity fail-open to avoid local baseline edits blocking startup)
$agentCmd = "`$env:AGENT_FAIL_ON_TAMPER='0'; Set-Location '$root\\agent'; & '$pythonPath' -m agent.main"
$agentProc = Start-Process powershell -ArgumentList "-Command", $agentCmd -WindowStyle Normal -PassThru

Write-Host "" 
Write-Host "Launched:" -ForegroundColor Green
Write-Host "  Backend  : http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "  Frontend : http://127.0.0.1:5173" -ForegroundColor Green
Write-Host "  Admin USB: http://127.0.0.1:5173/admin/usb-events" -ForegroundColor Green
Write-Host "" 
Write-Host "Login as admin/superadmin and open Admin -> USB Events." -ForegroundColor Yellow
Write-Host "Insert/remove USB and data will auto-refresh in the USB Events page." -ForegroundColor Yellow
Write-Host "" 
Write-Host "This launcher will keep running and stop Agent + Frontend when Backend stops." -ForegroundColor Cyan

# Supervise until backend stops
$startupGraceSeconds = 30
$maxConsecutiveFailures = 5
$consecutiveFailures = 0
$startTime = Get-Date

while ($true) {
    Start-Sleep -Seconds 3

    if ($backendProc.HasExited) {
        break
    }

    try {
        $probe = Invoke-WebRequest -Uri "http://127.0.0.1:8000/docs" -UseBasicParsing -TimeoutSec 2
        if ($probe -and $probe.StatusCode -ge 200 -and $probe.StatusCode -lt 500) {
            $consecutiveFailures = 0
            continue
        }
    } catch {
        # handled below via failure counter
    }

    $elapsed = ((Get-Date) - $startTime).TotalSeconds
    if ($elapsed -lt $startupGraceSeconds) {
        continue
    }

    $consecutiveFailures += 1
    if ($consecutiveFailures -ge $maxConsecutiveFailures) {
        break
    }
}

Write-Host "Backend stopped. Stopping frontend and agent..." -ForegroundColor Yellow

try { if ($frontendProc -and -not $frontendProc.HasExited) { Stop-Process -Id $frontendProc.Id -Force -ErrorAction SilentlyContinue } } catch {}
try { if ($agentProc -and -not $agentProc.HasExited) { Stop-Process -Id $agentProc.Id -Force -ErrorAction SilentlyContinue } } catch {}

Write-Host "All services stopped." -ForegroundColor Green
