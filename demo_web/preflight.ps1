[CmdletBinding()]
param(
    [switch]$RequireDynamic,
    [switch]$SkipDynamic,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
if ($RequireDynamic -and $SkipDynamic) {
    throw "RequireDynamic and SkipDynamic cannot be used together."
}

$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
. (Join-Path $DemoRoot "scripts\portable_runtime.ps1")

$SkillPython = Join-Path $ProjectRoot ".runtime_skill\Scripts\python.exe"
$SkillScanner = Join-Path $ProjectRoot ".runtime_skill\Scripts\skill-scanner.exe"
$McpPython = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
$McpScanner = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\mcp-scanner.exe"
$PipAudit = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\pip-audit.exe"
$PolicyPath = Join-Path $DemoRoot "config\admission_policy.yaml"
$ClosureConfigPath = Join-Path $DemoRoot "config\docker_skill_closure_backend.json"
$FrontendManifest = Join-Path $DemoRoot "frontend\package.json"
$FrontendLock = Join-Path $DemoRoot "frontend\pnpm-lock.yaml"
$ExpectedSkillVersion = "2.0.13.dev3+g4dee90371"
$ExpectedMcpVersion = "4.8.2"
$Checks = @()

function Add-Check {
    param(
        [string]$Id,
        [string]$Label,
        [ValidateSet("PASS", "WARN", "FAIL", "SKIP")][string]$Status,
        [bool]$Required,
        [string]$Message,
        [string]$Detail = ""
    )
    $script:Checks += [pscustomobject]@{
        id = $Id
        label = $Label
        status = $Status
        required = $Required
        message = $Message
        detail = $Detail
    }
}

function Invoke-CapturedCommand {
    param(
        [string]$Command,
        [string[]]$Arguments,
        [string]$WorkingDirectory = ""
    )
    $priorLocation = Get-Location
    try {
        if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }
        $output = & $Command @Arguments 2>&1 | Out-String
        return [pscustomobject]@{
            exit_code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
            output = $output.Trim()
        }
    } catch {
        return [pscustomobject]@{
            exit_code = 1
            output = $_.Exception.Message
        }
    } finally {
        Set-Location -LiteralPath $priorLocation
    }
}

function Test-RequiredFile {
    param([string]$Id, [string]$Label, [string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Add-Check $Id $Label "PASS" $true "Available" $Path
    } else {
        Add-Check $Id $Label "FAIL" $true "Missing; run bootstrap_runtimes.ps1 or follow QUICKSTART.md" $Path
    }
}

Add-Check "project_root" "Project root" "PASS" $true "Resolved from script location" $ProjectRoot
Test-RequiredFile "skill_python" "Skill Python" $SkillPython
Test-RequiredFile "skill_scanner" "Cisco Skill Scanner" $SkillScanner
Test-RequiredFile "mcp_python" "MCP Python" $McpPython
Test-RequiredFile "mcp_scanner" "Cisco MCP Scanner" $McpScanner
Test-RequiredFile "pip_audit" "pip-audit" $PipAudit
Test-RequiredFile "policy" "Admission policy" $PolicyPath
Test-RequiredFile "frontend_manifest" "Frontend package manifest" $FrontendManifest
Test-RequiredFile "frontend_lock" "Frontend frozen lockfile" $FrontendLock

if (Test-Path -LiteralPath $SkillPython -PathType Leaf) {
    $result = Invoke-CapturedCommand $SkillPython @("-c", "import importlib.metadata as m; print(m.version('cisco-ai-skill-scanner'))")
    if ($result.exit_code -eq 0 -and $result.output -eq $ExpectedSkillVersion) {
        Add-Check "skill_version" "Cisco Skill Scanner version" "PASS" $true $result.output $ExpectedSkillVersion
    } else {
        Add-Check "skill_version" "Cisco Skill Scanner version" "FAIL" $true "Expected $ExpectedSkillVersion" $result.output
    }
}

if (Test-Path -LiteralPath $McpPython -PathType Leaf) {
    $result = Invoke-CapturedCommand $McpPython @("-c", "import importlib.metadata as m; print(m.version('cisco-ai-mcp-scanner'))")
    if ($result.exit_code -eq 0 -and $result.output -eq $ExpectedMcpVersion) {
        Add-Check "mcp_version" "Cisco MCP Scanner version" "PASS" $true $result.output $ExpectedMcpVersion
    } else {
        Add-Check "mcp_version" "Cisco MCP Scanner version" "FAIL" $true "Expected $ExpectedMcpVersion" $result.output
    }

    $backendResult = Invoke-CapturedCommand $McpPython @("-c", "import fastapi, uvicorn, multipart; print('ready')")
    if ($backendResult.exit_code -eq 0 -and $backendResult.output -eq "ready") {
        Add-Check "backend_runtime" "FastAPI runtime" "PASS" $true "Import check passed"
    } else {
        Add-Check "backend_runtime" "FastAPI runtime" "FAIL" $true "Backend dependencies are incomplete" $backendResult.output
    }
}

if ((Test-Path -LiteralPath $PolicyPath -PathType Leaf) -and (Test-Path -LiteralPath $McpPython -PathType Leaf)) {
    $policyResult = Invoke-CapturedCommand $McpPython @("-c", "from backend.policy import load_policy; p=load_policy(); print(p.policy_id + '@' + p.version)") $DemoRoot
    if ($policyResult.exit_code -eq 0 -and $policyResult.output) {
        $policyHash = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Add-Check "policy_load" "Admission policy load" "PASS" $true $policyResult.output $policyHash
    } else {
        Add-Check "policy_load" "Admission policy load" "FAIL" $true "Policy cannot be loaded fail-closed" $policyResult.output
    }
}

try {
    $packageManager = Resolve-AegisPackageManager
    if ($packageManager) {
        $versionArgs = @($packageManager.PrefixArguments) + @("--version")
        $managerResult = Invoke-CapturedCommand $packageManager.Command $versionArgs
        if ($managerResult.exit_code -eq 0 -and $managerResult.output) {
            Add-Check "package_manager" "Frontend package manager" "PASS" $true $packageManager.DisplayName $managerResult.output
        } else {
            Add-Check "package_manager" "Frontend package manager" "FAIL" $true "Found but cannot execute" $managerResult.output
        }
    } else {
        Add-Check "package_manager" "Frontend package manager" "FAIL" $true "Install Node.js with Corepack or pnpm, then retry"
    }
} catch {
    Add-Check "package_manager" "Frontend package manager" "FAIL" $true $_.Exception.Message
}

try {
    $dataDirectory = Join-Path $DemoRoot "data"
    New-Item -ItemType Directory -Force -Path $dataDirectory | Out-Null
    $probePath = Join-Path $dataDirectory (".preflight-" + [Guid]::NewGuid().ToString("N") + ".tmp")
    [IO.File]::WriteAllText($probePath, "aegis-preflight", [Text.Encoding]::UTF8)
    Remove-Item -LiteralPath $probePath -Force
    Add-Check "data_write" "Runtime data directory" "PASS" $true "Create/write/delete probe passed" $dataDirectory
} catch {
    Add-Check "data_write" "Runtime data directory" "FAIL" $true "Runtime data directory is not writable" $_.Exception.Message
}

$DynamicIds = @("dynamic_config", "admin_token", "docker_cli", "docker_engine", "docker_image")
if ($SkipDynamic) {
    foreach ($id in $DynamicIds) {
        Add-Check $id $id "SKIP" $false "Dynamic checks skipped explicitly"
    }
} else {
    $dynamicRequired = [bool]$RequireDynamic
    if (Test-Path -LiteralPath $ClosureConfigPath -PathType Leaf) {
        Add-Check "dynamic_config" "Skill closure config" "PASS" $dynamicRequired "Available" $ClosureConfigPath
    } else {
        Add-Check "dynamic_config" "Skill closure config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Missing" $ClosureConfigPath
    }

    $adminToken = [Environment]::GetEnvironmentVariable("AEGIS_ADMIN_TOKEN", "Process")
    if ($adminToken -and $adminToken.Length -ge 16) {
        Add-Check "admin_token" "Administrator token" "PASS" $dynamicRequired "Configured in process environment" "length>=16; value not retained"
    } else {
        Add-Check "admin_token" "Administrator token" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Set AEGIS_ADMIN_TOKEN to at least 16 characters for dynamic audit"
    }

    try {
        $docker = Resolve-AegisDockerCli
    } catch {
        $docker = $null
        $dockerDiscoveryError = $_.Exception.Message
    }
    if ($docker) {
        Add-Check "docker_cli" "Docker CLI" "PASS" $dynamicRequired "Available" $docker
        $engineResult = Invoke-CapturedCommand $docker @("--context", "desktop-linux", "version", "--format", "{{json .Server}}")
        if ($engineResult.exit_code -eq 0 -and $engineResult.output) {
            try {
                $engine = $engineResult.output | ConvertFrom-Json
                $engineVersion = [string]$engine.Version
                $apiVersion = [string]$(if ($engine.ApiVersion) { $engine.ApiVersion } else { $engine.APIVersion })
                Add-Check "docker_engine" "Docker Linux engine" "PASS" $dynamicRequired "Engine $engineVersion / API $apiVersion" "context=desktop-linux"
            } catch {
                Add-Check "docker_engine" "Docker Linux engine" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Engine response was not valid JSON" $engineResult.output
            }
        } else {
            Add-Check "docker_engine" "Docker Linux engine" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Start Docker Desktop and the Linux engine" $engineResult.output
        }

        if (Test-Path -LiteralPath $ClosureConfigPath -PathType Leaf) {
            $closureConfig = Get-Content -LiteralPath $ClosureConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $imageReference = [string]$closureConfig.image.reference
            $expectedImageId = [string]$closureConfig.image.id
            $imageResult = Invoke-CapturedCommand $docker @("--context", "desktop-linux", "image", "inspect", $imageReference, "--format", "{{json .Id}}")
            $actualImageId = $imageResult.output.Trim('"')
            if ($imageResult.exit_code -eq 0 -and $actualImageId -eq $expectedImageId) {
                Add-Check "docker_image" "Hash-locked Docker image" "PASS" $dynamicRequired "Digest and image ID match" $actualImageId
            } else {
                Add-Check "docker_image" "Hash-locked Docker image" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Required local image is missing or mismatched; preflight never pulls it" $imageResult.output
            }
        } else {
            Add-Check "docker_image" "Hash-locked Docker image" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Cannot verify without closure config"
        }
    } else {
        $dockerMessage = if ($dockerDiscoveryError) { $dockerDiscoveryError } else { "Install or start Docker Desktop" }
        Add-Check "docker_cli" "Docker CLI" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired $dockerMessage
        Add-Check "docker_engine" "Docker Linux engine" "SKIP" $dynamicRequired "Docker CLI unavailable"
        Add-Check "docker_image" "Hash-locked Docker image" "SKIP" $dynamicRequired "Docker CLI unavailable"
    }
}

$RequiredFailures = @($Checks | Where-Object { $_.required -and $_.status -eq "FAIL" }).Count
$Warnings = @($Checks | Where-Object { $_.status -eq "WARN" }).Count
$DynamicReady = -not $SkipDynamic -and @($Checks | Where-Object { $DynamicIds -contains $_.id -and $_.status -ne "PASS" }).Count -eq 0
$Summary = [pscustomobject]@{
    schema_version = "1.0"
    profile = if ($SkipDynamic) { "static-only" } elseif ($RequireDynamic) { "full-required" } else { "portable-start" }
    ready = $RequiredFailures -eq 0
    dynamic_ready = $DynamicReady
    required_failures = $RequiredFailures
    warnings = $Warnings
    project_root = $ProjectRoot
    checks = $Checks
}

if ($Json) {
    $Summary | ConvertTo-Json -Depth 8
} else {
    Write-Host "Aegis Chain preflight ($($Summary.profile))"
    $Checks | Select-Object status, required, label, message | Format-Table -AutoSize
    if ($Summary.ready) {
        Write-Host "Preflight passed. Dynamic ready: $DynamicReady. Warnings: $Warnings."
    } else {
        Write-Error "Preflight failed with $RequiredFailures required check(s)."
    }
}

if ($Summary.ready) { exit 0 }
exit 1
