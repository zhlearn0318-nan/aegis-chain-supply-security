[CmdletBinding()]
param([switch]$NoBrowser)

$ErrorActionPreference = "Stop"
$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
$Frontend = Join-Path $DemoRoot "frontend"
$Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
$Pnpm = "C:\Users\23684\.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pnpm.cmd"
$PidFile = Join-Path $DemoRoot ".server.pid"
$LogDir = Join-Path $DemoRoot "logs"
$Url = "http://127.0.0.1:8000"

$AdminToken = [Environment]::GetEnvironmentVariable("AEGIS_ADMIN_TOKEN", "Process")
if ([string]::IsNullOrEmpty($AdminToken) -or $AdminToken.Length -lt 16) {
    Write-Warning "AEGIS_ADMIN_TOKEN is not set to at least 16 characters. Static scanning will work, but administrator dynamic audit will fail closed with HTTP 503."
}

foreach ($required in @($Python, $Pnpm)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing runtime component: $required"
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $Frontend "node_modules"))) {
    Push-Location $Frontend
    try { & $Pnpm install } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "Frontend dependency installation failed." }
}

Push-Location $Frontend
try { & $Pnpm run build } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }

# Treat the v1 health contract as the source of truth. An empty/stale PID file
# must never turn PID 0 (System Idle Process) into a false "already running".
$existingResponse = $null
try {
    $existingResponse = Invoke-WebRequest -UseBasicParsing -Uri "$Url/api/v1/health" -TimeoutSec 2
} catch { }

if ($existingResponse) {
    $existingHealth = $null
    try { $existingHealth = $existingResponse.Content | ConvertFrom-Json } catch { }
    if ($existingHealth.api_version -eq "v1" -and $existingHealth.data.status -in @("ready", "degraded")) {
        $listener = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($listener) { $listener.OwningProcess | Set-Content -LiteralPath $PidFile -Encoding ascii }
        Write-Host "Demo is already running: $Url"
        if (-not $NoBrowser) { Start-Process $Url }
        return
    }
    throw "Port 8000 is occupied by a service that does not expose the Aegis Chain API v1 contract. Stop or move that service, then retry."
}

$listenerText = netstat -ano | Select-String -Pattern '^\s*TCP\s+127\.0\.0\.1:8000\s+.*LISTENING\s+\d+\s*$' | Select-Object -First 1
if ($listenerText) {
    throw "Port 8000 is already occupied, but its health endpoint is unavailable. Stop or move the owning service, then retry. Listener: $($listenerText.Line.Trim())"
}

if (Test-Path -LiteralPath $PidFile) {
    Remove-Item -LiteralPath $PidFile -Force
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$StdoutLog = Join-Path $LogDir "server.out.log"
$StderrLog = Join-Path $LogDir "server.err.log"

# Some host tools inject both Path and PATH. Windows PowerShell treats them as
# duplicate keys when Start-Process clones the environment, so normalize them.
$ProcessPath = [Environment]::GetEnvironmentVariable("PATH", "Process")
[Environment]::SetEnvironmentVariable("Path", $null, "Process")
[Environment]::SetEnvironmentVariable("PATH", $ProcessPath, "Process")

$server = Start-Process `
    -FilePath $Python `
    -ArgumentList @("-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "info") `
    -WorkingDirectory $DemoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -PassThru
$server.Id | Set-Content -LiteralPath $PidFile -Encoding ascii

$ready = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    Start-Sleep -Milliseconds 250
    try {
        $health = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 2
        if ($health.status -in @("ready", "degraded")) { $ready = $true; break }
    } catch { }
}
if (-not $ready) {
    $errorTail = if (Test-Path -LiteralPath $StderrLog) {
        (Get-Content -LiteralPath $StderrLog -Tail 20 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
    } else { "No error log was produced." }
    throw "Demo failed to start. Check whether port 8000 is occupied.`n$errorTail"
}

$listener = Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) { $listener.OwningProcess | Set-Content -LiteralPath $PidFile -Encoding ascii }

Write-Host "Demo started: $Url"
Write-Host "Stop it with .\stop_demo.ps1"
Write-Host "Logs: $StdoutLog and $StderrLog"
if (-not $NoBrowser) { Start-Process $Url }
