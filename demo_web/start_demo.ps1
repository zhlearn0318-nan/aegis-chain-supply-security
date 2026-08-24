[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$RequireDynamic,
    [ValidateRange(1024, 65535)][int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
$Frontend = Join-Path $DemoRoot "frontend"
$Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
$PidFile = Join-Path $DemoRoot ".server.pid"
$LogDir = Join-Path $DemoRoot "logs"
$Url = "http://127.0.0.1:$Port"
$Preflight = Join-Path $DemoRoot "preflight.ps1"
. (Join-Path $DemoRoot "scripts\portable_runtime.ps1")

$PowerShellHost = (Get-Process -Id $PID).Path
$preflightArguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Preflight)
if ($RequireDynamic) { $preflightArguments += "-RequireDynamic" }
& $PowerShellHost @preflightArguments
if ($LASTEXITCODE -ne 0) {
    throw "Startup preflight failed. Resolve the FAIL items above and retry."
}

$PackageManager = Resolve-AegisPackageManager
if (-not $PackageManager) {
    throw "No frontend package manager found. Install Node.js with Corepack or pnpm, then retry."
}

if (-not (Test-Path -LiteralPath (Join-Path $Frontend "node_modules"))) {
    Push-Location $Frontend
    try {
        Invoke-AegisPackageManager $PackageManager @("install", "--frozen-lockfile") "Frontend dependency installation failed."
    } finally { Pop-Location }
}

Push-Location $Frontend
try {
    Invoke-AegisPackageManager $PackageManager @("run", "build") "Frontend build failed."
} finally { Pop-Location }

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
        $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($listener) { $listener.OwningProcess | Set-Content -LiteralPath $PidFile -Encoding ascii }
        Write-Host "Demo is already running: $Url"
        if (-not $NoBrowser) { Start-Process $Url }
        return
    }
    throw "Port $Port is occupied by a service that does not expose the Aegis Chain API v1 contract. Stop or move that service, or retry with -Port <another port>."
}

$listenerText = netstat -ano | Select-String -Pattern "^\s*TCP\s+\S+:$Port\s+.*LISTENING\s+\d+\s*$" | Select-Object -First 1
if ($listenerText) {
    throw "Port $Port is already occupied, but its health endpoint is unavailable. Stop or move the owning service, or retry with -Port <another port>. Listener: $($listenerText.Line.Trim())"
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
    -ArgumentList @("-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", $Port, "--log-level", "info") `
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
        $health = Invoke-RestMethod -Uri "$Url/api/v1/health" -TimeoutSec 2
        if ($health.api_version -eq "v1" -and $health.data.status -in @("ready", "degraded")) {
            $ready = $true
            break
        }
    } catch { }
}
if (-not $ready) {
    $errorTail = if (Test-Path -LiteralPath $StderrLog) {
        (Get-Content -LiteralPath $StderrLog -Tail 20 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
    } else { "No error log was produced." }
    throw "Demo failed to start. Check whether port 8000 is occupied.`n$errorTail"
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) { $listener.OwningProcess | Set-Content -LiteralPath $PidFile -Encoding ascii }

Write-Host "Demo started: $Url"
Write-Host "Stop it with .\stop_demo.ps1"
Write-Host "Logs: $StdoutLog and $StderrLog"
if (-not $NoBrowser) { Start-Process $Url }
