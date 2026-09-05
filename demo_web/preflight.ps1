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

$SkillPython = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $ProjectRoot ".runtime_skill")
$SkillScanner = Join-Path $ProjectRoot ".runtime_skill\Scripts\skill-scanner.exe"
$McpPython = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $ProjectRoot ".runtime_mcp313")
$McpScanner = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\mcp-scanner.exe"
$PipAudit = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\pip-audit.exe"
Add-AegisRuntimeToPath -RuntimeRoots @(
    (Join-Path $ProjectRoot ".runtime_skill"),
    (Join-Path $ProjectRoot ".runtime_mcp313")
) | Out-Null
$PolicyPath = Join-Path $DemoRoot "config\admission_policy.yaml"
$ClosureConfigPath = Join-Path $DemoRoot "config\skill_dynamic_sandbox_v2.json"
$SemanticConfigPath = Join-Path $DemoRoot "config\skill_semantic_model.json"
$FrontendManifest = Join-Path $DemoRoot "frontend\package.json"
$FrontendLock = Join-Path $DemoRoot "frontend\pnpm-lock.yaml"
$BackendLock = Join-Path $DemoRoot "backend\requirements.lock"
$RuntimeSecurityLock = Join-Path $DemoRoot "backend\runtime-security.lock"
$BackendLockVerifier = Join-Path $DemoRoot "tools\supply_chain\verify_installed_python_lock.py"
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
Test-RequiredFile "backend_lock" "Backend hash lockfile" $BackendLock
Test-RequiredFile "runtime_security_lock" "Shared runtime security lock" $RuntimeSecurityLock

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

    if ((Test-Path -LiteralPath $BackendLock -PathType Leaf) -and
        (Test-Path -LiteralPath $RuntimeSecurityLock -PathType Leaf) -and
        (Test-Path -LiteralPath $BackendLockVerifier -PathType Leaf)) {
        $lockResult = Invoke-CapturedCommand $McpPython @($BackendLockVerifier, $BackendLock)
        if ($lockResult.exit_code -eq 0) {
            Add-Check "backend_lock_match" "Installed backend hash lock" "PASS" $true "Installed versions match" $lockResult.output
        } else {
            Add-Check "backend_lock_match" "Installed backend hash lock" "FAIL" $true "Run bootstrap_runtimes.ps1 -Component Mcp" $lockResult.output
        }
        $securityLockResult = Invoke-CapturedCommand $McpPython @($BackendLockVerifier, $RuntimeSecurityLock)
        if ($securityLockResult.exit_code -eq 0) {
            Add-Check "runtime_security_lock_match" "Installed security overlay" "PASS" $true "Installed versions match" $securityLockResult.output
        } else {
            Add-Check "runtime_security_lock_match" "Installed security overlay" "FAIL" $true "Run bootstrap_runtimes.ps1 -Component Mcp" $securityLockResult.output
        }
    } else {
        Add-Check "backend_lock_match" "Installed backend hash lock" "FAIL" $true "Lock verifier is unavailable"
        Add-Check "runtime_security_lock_match" "Installed security overlay" "FAIL" $true "Lock verifier is unavailable"
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

$DynamicIds = @("dynamic_config", "admin_token", "docker_cli", "docker_engine", "docker_images", "semantic_config", "semantic_runtime", "semantic_model")
if ($SkipDynamic) {
    foreach ($id in $DynamicIds) {
        Add-Check $id $id "SKIP" $false "Dynamic checks skipped explicitly"
    }
} else {
    $dynamicRequired = [bool]$RequireDynamic
    if (Test-Path -LiteralPath $ClosureConfigPath -PathType Leaf) {
        $configResult = Invoke-CapturedCommand $McpPython @("-c", "from backend.dynamic_audit.skill_sandbox_multiruntime import load_multiruntime_config; print(load_multiruntime_config().sha256)") $DemoRoot
        if ($configResult.exit_code -eq 0 -and $configResult.output) {
            Add-Check "dynamic_config" "Multi-runtime sandbox config" "PASS" $dynamicRequired "Identity, tool hashes and security policy verified" $configResult.output
        } else {
            Add-Check "dynamic_config" "Multi-runtime sandbox config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Configuration or tool hash validation failed" $configResult.output
        }
    } else {
        Add-Check "dynamic_config" "Multi-runtime sandbox config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Missing" $ClosureConfigPath
    }

    if (Test-Path -LiteralPath $SemanticConfigPath -PathType Leaf) {
        try {
            $semanticConfig = Get-Content -LiteralPath $SemanticConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $semanticModelName = [string]$semanticConfig.local.model
            if ($semanticConfig.default_mode -eq "local" -and $semanticModelName -and -not [bool]$semanticConfig.external.enabled) {
                Add-Check "semantic_config" "Semantic model config" "PASS" $dynamicRequired "Local-first; external API disabled by default" $semanticModelName
            } else {
                Add-Check "semantic_config" "Semantic model config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Local model is not selected"
            }
        } catch {
            Add-Check "semantic_config" "Semantic model config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Invalid JSON" $_.Exception.Message
            $semanticModelName = ""
        }
    } else {
        Add-Check "semantic_config" "Semantic model config" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Missing" $SemanticConfigPath
        $semanticModelName = ""
    }

    $ollama = Resolve-AegisOllamaCli
    if ($ollama) {
        Add-Check "semantic_runtime" "Ollama local runtime" "PASS" $dynamicRequired "Available" $ollama
        if ($semanticModelName) {
            $modelResult = Invoke-CapturedCommand $ollama @("show", $semanticModelName)
            if ($modelResult.exit_code -eq 0) {
                Add-Check "semantic_model" "Selected local semantic model" "PASS" $dynamicRequired "Available" $semanticModelName
            } else {
                Add-Check "semantic_model" "Selected local semantic model" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Run: ollama pull $semanticModelName" $modelResult.output
            }
        } else {
            Add-Check "semantic_model" "Selected local semantic model" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "No valid model is configured"
        }
    } else {
        Add-Check "semantic_runtime" "Ollama local runtime" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Install Ollama or configure AEGIS_OLLAMA_COMMAND"
        Add-Check "semantic_model" "Selected local semantic model" "SKIP" $dynamicRequired "Ollama is unavailable"
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
            $imageChecks = @()
            foreach ($image in @($closureConfig.images.psobject.Properties.Value | Sort-Object reference -Unique)) {
                $imageReference = [string]$image.reference
                $expectedImageId = [string]$image.id
                $imageResult = Invoke-CapturedCommand $docker @("--context", "desktop-linux", "image", "inspect", $imageReference, "--format", "{{json .Id}}")
                $actualImageId = $imageResult.output.Trim('"')
                $imageChecks += [pscustomobject]@{ reference = $imageReference; expected = $expectedImageId; actual = $actualImageId; pass = $imageResult.exit_code -eq 0 -and $actualImageId -eq $expectedImageId }
            }
            if ($imageChecks.Count -gt 0 -and @($imageChecks | Where-Object { -not $_.pass }).Count -eq 0) {
                Add-Check "docker_images" "Hash-locked runtime images" "PASS" $dynamicRequired "All unique image digests and IDs match" (($imageChecks.reference) -join "; ")
            } else {
                Add-Check "docker_images" "Hash-locked runtime images" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "A required local image is missing or mismatched; preflight never pulls images" ($imageChecks | ConvertTo-Json -Compress)
            }
        } else {
            Add-Check "docker_images" "Hash-locked runtime images" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired "Cannot verify without sandbox config"
        }
    } else {
        $dockerMessage = if ($dockerDiscoveryError) { $dockerDiscoveryError } else { "Install or start Docker Desktop" }
        Add-Check "docker_cli" "Docker CLI" $(if ($dynamicRequired) { "FAIL" } else { "WARN" }) $dynamicRequired $dockerMessage
        Add-Check "docker_engine" "Docker Linux engine" "SKIP" $dynamicRequired "Docker CLI unavailable"
        Add-Check "docker_images" "Hash-locked runtime images" "SKIP" $dynamicRequired "Docker CLI unavailable"
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
