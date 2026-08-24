[CmdletBinding()]
param(
    [ValidateSet("All", "Skill", "Mcp")][string]$Component = "All",
    [string]$WheelDirectory = "",
    [string]$SkillWheelSha256 = "",
    [string]$McpWheelSha256 = "",
    [switch]$Offline,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
. (Join-Path $ProjectRoot "demo_web\scripts\portable_runtime.ps1")

if ([string]::IsNullOrWhiteSpace($WheelDirectory)) {
    $WheelDirectory = Join-Path $ProjectRoot "results\wheels"
} elseif (-not [IO.Path]::IsPathRooted($WheelDirectory)) {
    $WheelDirectory = Join-Path $ProjectRoot $WheelDirectory
}

$RuntimeDefinitions = @(
    [pscustomobject]@{
        Id = "Skill"
        Label = "Cisco Skill Scanner"
        Runtime = Join-Path $ProjectRoot ".runtime_skill"
        PythonVersion = "3.11"
        CondaPackages = @("python=3.11", "pip")
        LockFile = Join-Path $ProjectRoot "results\skill_scanner_locked_requirements.txt"
        PackageName = "cisco-ai-skill-scanner"
        Version = "2.0.13.dev3+g4dee90371"
        EntryPoint = "skill-scanner.exe"
        SourceUrl = "https://github.com/cisco-ai-defense/skill-scanner.git"
        SourceCommit = "4dee90371890ff23e1b21ea974e02847eacaa464"
        SourceDirectory = Join-Path $ProjectRoot "third_party\skill-scanner"
        WheelName = "cisco_ai_skill_scanner-2.0.13.dev3+g4dee90371-py3-none-any.whl"
    },
    [pscustomobject]@{
        Id = "Mcp"
        Label = "Cisco MCP Scanner"
        Runtime = Join-Path $ProjectRoot ".runtime_mcp313"
        PythonVersion = "3.13"
        CondaPackages = @("--channel", "conda-forge", "python=3.13", "rust=1.96", "pip")
        LockFile = Join-Path $ProjectRoot "results\mcp_scanner_locked_requirements.txt"
        PackageName = "cisco-ai-mcp-scanner"
        Version = "4.8.2"
        EntryPoint = "mcp-scanner.exe"
        SourceUrl = "https://github.com/cisco-ai-defense/mcp-scanner.git"
        SourceCommit = "51966cce214ae057e69c3a672307911f5026e255"
        SourceDirectory = Join-Path $ProjectRoot "third_party\mcp-scanner"
        WheelName = "cisco_ai_mcp_scanner-4.8.2-py3-none-any.whl"
    }
)

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage
    )

    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE"
    }
}

function Get-RuntimePython {
    param($Definition)
    return Join-Path $Definition.Runtime "Scripts\python.exe"
}

function Test-Runtime {
    param($Definition, [switch]$Quiet)

    $python = Get-RuntimePython $Definition
    $entryPoint = Join-Path $Definition.Runtime ("Scripts\" + $Definition.EntryPoint)
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        if (-not $Quiet) { Write-Warning "$($Definition.Label): Python runtime is missing at $python" }
        return $false
    }
    if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
        if (-not $Quiet) { Write-Warning "$($Definition.Label): entry point is missing at $entryPoint" }
        return $false
    }

    $versionScript = "import importlib.metadata as m; print(m.version('$($Definition.PackageName)'))"
    $actualVersion = (& $python -c $versionScript 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualVersion -ne $Definition.Version) {
        if (-not $Quiet) {
            Write-Warning "$($Definition.Label): expected $($Definition.Version), found '$actualVersion'."
        }
        return $false
    }

    if ($Definition.Id -eq "Mcp") {
        & $python -c "import fastapi, uvicorn, multipart; print('backend-ready')" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            if (-not $Quiet) { Write-Warning "$($Definition.Label): FastAPI runtime dependencies are incomplete." }
            return $false
        }
        $pipAudit = Join-Path $Definition.Runtime "Scripts\pip-audit.exe"
        if (-not (Test-Path -LiteralPath $pipAudit -PathType Leaf)) {
            if (-not $Quiet) { Write-Warning "$($Definition.Label): pip-audit entry point is missing." }
            return $false
        }
    }

    if (-not $Quiet) { Write-Host "PASS $($Definition.Label) $actualVersion ($python)" }
    return $true
}

function Resolve-Conda {
    $candidates = @()
    if ($env:ProgramData) {
        $candidates += Join-Path $env:ProgramData "miniconda3\Scripts\conda.exe"
        $candidates += Join-Path $env:ProgramData "anaconda3\Scripts\conda.exe"
    }
    if ($env:LOCALAPPDATA) {
        $candidates += Join-Path $env:LOCALAPPDATA "miniconda3\Scripts\conda.exe"
        $candidates += Join-Path $env:LOCALAPPDATA "anaconda3\Scripts\conda.exe"
    }
    return Resolve-AegisConfiguredApplication `
        -EnvironmentVariable "AEGIS_CONDA_COMMAND" `
        -Names @("conda.exe", "conda") `
        -Candidates $candidates
}

function Resolve-Git {
    return Resolve-AegisConfiguredApplication `
        -EnvironmentVariable "AEGIS_GIT_COMMAND" `
        -Names @("git.exe", "git")
}

function Get-VerifiedSource {
    param($Definition, [string]$Git)

    $source = $Definition.SourceDirectory
    if (Test-Path -LiteralPath $source) {
        if (-not (Test-Path -LiteralPath (Join-Path $source ".git") -PathType Container)) {
            throw "$source exists but is not the expected Git checkout. Move it aside manually and retry."
        }
        $actualCommit = (& $Git -C $source rev-parse HEAD 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $Definition.SourceCommit) {
            throw "$source is not at locked commit $($Definition.SourceCommit). Current: $actualCommit. Move it aside manually and retry."
        }
        return $source
    }

    if ($Offline) {
        throw "Offline mode needs the exact wheel $($Definition.WheelName); source download is disabled."
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $source -Parent) | Out-Null
    Invoke-CheckedCommand $Git @("clone", "--no-checkout", $Definition.SourceUrl, $source) "Clone failed for $($Definition.Label)."
    Invoke-CheckedCommand $Git @("-C", $source, "checkout", "--detach", $Definition.SourceCommit) "Checkout failed for $($Definition.Label)."
    $actualCommit = (& $Git -C $source rev-parse HEAD 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $Definition.SourceCommit) {
        throw "$($Definition.Label) source commit verification failed."
    }
    return $source
}

function Install-Runtime {
    param($Definition, [string]$Conda)

    if (Test-Path -LiteralPath $Definition.Runtime) {
        throw "$($Definition.Runtime) exists but failed verification. This script will not overwrite it. Move the directory aside manually, then retry."
    }
    if (-not (Test-Path -LiteralPath $Definition.LockFile -PathType Leaf)) {
        throw "Locked requirements are missing: $($Definition.LockFile)"
    }

    $wheel = $null
    if ($Offline) {
        $wheel = Join-Path $WheelDirectory $Definition.WheelName
        if (-not (Test-Path -LiteralPath $wheel -PathType Leaf)) {
            throw "Offline wheel is missing: $wheel"
        }
        $expectedWheelSha256 = if ($Definition.Id -eq "Skill") { $SkillWheelSha256 } else { $McpWheelSha256 }
        if ($expectedWheelSha256 -notmatch "^[0-9a-fA-F]{64}$") {
            throw "Offline mode requires the audited SHA-256 for $($Definition.WheelName). Use -$($Definition.Id)WheelSha256 <64 hex characters>."
        }
        $actualWheelSha256 = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash
        if ($actualWheelSha256 -ne $expectedWheelSha256) {
            throw "Offline wheel SHA-256 mismatch for $($Definition.WheelName). Expected $expectedWheelSha256; actual $actualWheelSha256."
        }
    }

    Write-Host "Creating $($Definition.Label) runtime with Python $($Definition.PythonVersion)..."
    $condaArguments = @("create", "--prefix", $Definition.Runtime) + @($Definition.CondaPackages) + @("--yes")
    Invoke-CheckedCommand $Conda $condaArguments "Conda environment creation failed for $($Definition.Label)."
    $python = Get-RuntimePython $Definition

    New-Item -ItemType Directory -Force -Path $WheelDirectory | Out-Null
    if (-not $Offline) {
        $git = Resolve-Git
        if (-not $git) { throw "Git is required to build the locked Cisco source revision." }
        $source = Get-VerifiedSource $Definition $git
        $buildDirectory = Join-Path $WheelDirectory ("verified-" + $Definition.Id.ToLowerInvariant() + "-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $buildDirectory | Out-Null
        Invoke-CheckedCommand $python @("-m", "pip", "wheel", "--no-deps", "--wheel-dir", $buildDirectory, $source) "Wheel build failed for $($Definition.Label)."
        $wheel = Join-Path $buildDirectory $Definition.WheelName
        if (-not (Test-Path -LiteralPath $wheel -PathType Leaf)) {
            throw "The locked source built successfully but the expected wheel name was not produced: $($Definition.WheelName)"
        }
        $builtWheelSha256 = (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "Built from locked source commit; wheel SHA-256: $builtWheelSha256"
    }

    $dependencyArguments = @("-m", "pip", "install", "--require-hashes", "-r", $Definition.LockFile)
    if ($Offline) {
        $dependencyArguments += @("--no-index", "--find-links", $WheelDirectory)
    }
    Invoke-CheckedCommand $python $dependencyArguments "Hash-locked dependency installation failed for $($Definition.Label)."
    Invoke-CheckedCommand $python @("-m", "pip", "install", "--no-deps", $wheel) "Cisco scanner installation failed for $($Definition.Label)."

    if (-not (Test-Runtime $Definition -Quiet)) {
        throw "$($Definition.Label) did not pass post-install verification."
    }
    Write-Host "PASS $($Definition.Label) was rebuilt and verified."
}

$SelectedDefinitions = @($RuntimeDefinitions | Where-Object { $Component -eq "All" -or $_.Id -eq $Component })
if ($SelectedDefinitions.Count -eq 0) { throw "No runtime selected." }

if ($VerifyOnly) {
    $failed = 0
    foreach ($definition in $SelectedDefinitions) {
        if (-not (Test-Runtime $definition)) { $failed++ }
    }
    if ($failed -gt 0) { throw "$failed selected runtime(s) failed verification." }
    Write-Host "All selected runtimes match the locked versions."
    exit 0
}

$Conda = Resolve-Conda
if (-not $Conda) {
    throw "Conda was not found. Install Miniconda/Anaconda or set AEGIS_CONDA_COMMAND, then retry."
}

foreach ($definition in $SelectedDefinitions) {
    if (Test-Runtime $definition -Quiet) {
        Test-Runtime $definition | Out-Null
        Write-Host "Existing runtime is valid; no rebuild needed."
        continue
    }
    Install-Runtime $definition $Conda
}

Write-Host "Runtime bootstrap completed. Run .\demo_web\preflight.ps1 to verify the whole platform."
