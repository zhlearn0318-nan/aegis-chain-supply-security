[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [switch]$WriteRepositoryArtifacts
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
. (Join-Path $DemoRoot "scripts\portable_runtime.ps1")

$Python = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $ProjectRoot ".runtime_mcp313")
$PipAudit = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\pip-audit.exe"
Add-AegisRuntimeToPath -RuntimeRoots @((Join-Path $ProjectRoot ".runtime_mcp313")) | Out-Null
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "MCP Python runtime is missing. Run .\bootstrap_runtimes.ps1 -Component Mcp first."
}
if (-not (Test-Path -LiteralPath $PipAudit -PathType Leaf)) {
    throw "pip-audit is missing from the MCP runtime."
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $DemoRoot "data\project-supply-chain-latest"
} elseif (-not [IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $ProjectRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$PythonAudit = Join-Path $OutputDirectory "python-audit.json"
$RuntimeAudit = Join-Path $OutputDirectory "python-shared-runtime-audit.json"
$NodeAudit = Join-Path $OutputDirectory "node-audit.json"
$NodeLicenses = Join-Path $OutputDirectory "node-licenses.json"
$PipCache = Join-Path $DemoRoot "data\pip-audit-project-cache"
New-Item -ItemType Directory -Force -Path $PipCache | Out-Null

& $Python -m pip_audit `
    --requirement (Join-Path $DemoRoot "backend\requirements-dev.lock") `
    --format json `
    --output $PythonAudit `
    --progress-spinner off `
    --cache-dir $PipCache `
    --vulnerability-service osv `
    --timeout 20 `
    --disable-pip
$PythonAuditExit = $LASTEXITCODE
if ($PythonAuditExit -ne 0 -or -not (Test-Path -LiteralPath $PythonAudit -PathType Leaf)) {
    throw "Python vulnerability audit failed closed with exit code $PythonAuditExit."
}

& $Python -m pip_audit `
    --local `
    --format json `
    --output $RuntimeAudit `
    --progress-spinner off `
    --cache-dir $PipCache `
    --vulnerability-service osv `
    --timeout 20
$RuntimeAuditExit = $LASTEXITCODE
if ($RuntimeAuditExit -ne 0 -or -not (Test-Path -LiteralPath $RuntimeAudit -PathType Leaf)) {
    throw "Shared Python runtime vulnerability audit failed closed with exit code $RuntimeAuditExit."
}

$PackageManager = Resolve-AegisPackageManager
if (-not $PackageManager) {
    throw "pnpm or Corepack is required for the frontend audit."
}
$PreviousLocation = Get-Location
try {
    Set-Location -LiteralPath (Join-Path $DemoRoot "frontend")
    $AuditArguments = @($PackageManager.PrefixArguments) + @("audit", "--json")
    $AuditText = (& $PackageManager.Command @AuditArguments 2>&1 | Out-String).Trim()
    $NodeAuditExit = $LASTEXITCODE
    [IO.File]::WriteAllText($NodeAudit, $AuditText + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    $LicenseArguments = @($PackageManager.PrefixArguments) + @("licenses", "list", "--json")
    $LicenseText = (& $PackageManager.Command @LicenseArguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "pnpm license inventory failed." }
    [IO.File]::WriteAllText($NodeLicenses, $LicenseText + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
} finally {
    Set-Location -LiteralPath $PreviousLocation
}

$Arguments = @(
    (Join-Path $DemoRoot "tools\supply_chain\audit_project_supply_chain.py"),
    "--project-root", $ProjectRoot,
    "--python-lock", (Join-Path $DemoRoot "backend\requirements.lock"),
    "--python-dev-lock", (Join-Path $DemoRoot "backend\requirements-dev.lock"),
    "--cisco-lock", (Join-Path $ProjectRoot "results\mcp_scanner_locked_requirements.txt"),
    "--security-lock", (Join-Path $DemoRoot "backend\runtime-security.lock"),
    "--package-json", (Join-Path $DemoRoot "frontend\package.json"),
    "--pnpm-lock", (Join-Path $DemoRoot "frontend\pnpm-lock.yaml"),
    "--pip-audit", $PythonAudit,
    "--runtime-audit", $RuntimeAudit,
    "--pnpm-audit", $NodeAudit,
    "--node-licenses", $NodeLicenses,
    "--policy", (Join-Path $DemoRoot "config\project_supply_chain_policy.json"),
    "--output", $OutputDirectory
)
if ($WriteRepositoryArtifacts) { $Arguments += "--write-artifacts" }
& $Python @Arguments
$SelfAuditExit = $LASTEXITCODE

if ($PythonAuditExit -ne 0 -or $RuntimeAuditExit -ne 0 -or $NodeAuditExit -ne 0 -or $SelfAuditExit -ne 0) {
    throw "Project supply-chain gate failed. Review $OutputDirectory."
}
Write-Host "PASS Project supply-chain gate. Evidence: $OutputDirectory"
