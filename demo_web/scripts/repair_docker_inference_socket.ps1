[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
if (-not $env:LOCALAPPDATA -or -not $env:APPDATA) {
    throw "LOCALAPPDATA and APPDATA are required."
}
$localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
$stamp = [DateTimeOffset]::Now.ToString("yyyyMMdd-HHmmss") + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)
$backupRoot = [IO.Path]::GetFullPath((Join-Path $localRoot "AegisDockerRepair\$stamp"))
if (-not $backupRoot.StartsWith($localRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Backup path escaped LOCALAPPDATA."
}
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null

$errorFile = [IO.Path]::GetFullPath((Join-Path $localRoot "Docker\backend.error.json"))
if (-not (Test-Path -LiteralPath $errorFile -PathType Leaf)) {
    throw "Docker backend error report is missing; refusing an unverified repair."
}
$rawError = Get-Content -LiteralPath $errorFile -Raw
if ($rawError -notmatch "The file cannot be accessed by the system" -or $rawError -notmatch "Docker/run/dockerInference") {
    throw "The current Docker failure is not the verified dockerInference socket failure."
}

foreach ($name in @("Docker Desktop", "com.docker.backend", "docker", "DockerCli")) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force
}
Start-Sleep -Seconds 3

$settings = [IO.Path]::GetFullPath((Join-Path $env:APPDATA "Docker\settings-store.json"))
if (Test-Path -LiteralPath $settings -PathType Leaf) {
    $settingsRoot = [IO.Path]::GetFullPath((Split-Path -Parent $settings))
    if (-not $settings.StartsWith($settingsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Docker settings path escaped its expected root."
    }
    $settingsBackup = Join-Path $backupRoot "settings-store.json"
    Copy-Item -LiteralPath $settings -Destination $settingsBackup
    $payload = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    foreach ($entry in @(
        @{ Name = "EnableInference"; Value = $false },
        @{ Name = "InferenceCanUseGPUVariant"; Value = $false },
        @{ Name = "EnableDockerAI"; Value = $false }
    )) {
        if ($payload.PSObject.Properties.Name -contains $entry.Name) {
            $payload.($entry.Name) = $entry.Value
        } else {
            $payload | Add-Member -NotePropertyName $entry.Name -NotePropertyValue $entry.Value
        }
    }
    $temporary = Join-Path $backupRoot "settings-store.updated.json"
    [IO.File]::WriteAllText($temporary, ($payload | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $settings -Force
}

foreach ($relative in @("Docker\run", "docker-secrets-engine")) {
    $source = [IO.Path]::GetFullPath((Join-Path $localRoot $relative))
    if (-not $source.StartsWith($localRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Docker runtime path escaped LOCALAPPDATA."
    }
    if (-not (Test-Path -LiteralPath $source -PathType Container)) { continue }
    $unexpected = @(Get-ChildItem -LiteralPath $source -Force -ErrorAction Stop | Where-Object {
        -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $_.PSIsContainer
    })
    if ($unexpected.Count -gt 0) {
        throw "Refusing repair because the Docker runtime directory contains ordinary data: $source"
    }
    $destination = Join-Path $backupRoot (($relative -replace "[\\/]", "-") + ".stale")
    Move-Item -LiteralPath $source -Destination $destination
}

[pscustomobject]@{
    repaired = $true
    failure = "dockerInference_stale_windows_socket"
    backup_root = $backupRoot
    recoverable = $true
} | ConvertTo-Json -Compress
