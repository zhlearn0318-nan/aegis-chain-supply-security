[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$SkipDependencyInstall,
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ProjectRoot = $PSScriptRoot
$DemoRoot = Join-Path $ProjectRoot "demo_web"
$ExpectedOpenClawVersion = "2026.7.1-2"
$ExpectedPnpmVersion = "11.19.0"
$GatewayPort = 18789
$PluginRoot = Join-Path $DemoRoot "openclaw_plugin\aegis-admission-ui"
$DataRoot = Join-Path $DemoRoot "data\openclaw-final"
$RuntimePython = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
$InstallPolicyScript = Join-Path $DemoRoot "tools\openclaw_install_policy.py"
$AuditDb = Join-Path $DataRoot "admission_audit.db"
$CustomRules = Join-Path $DataRoot "custom_rules.json"
$DockerConfigFile = Join-Path $DemoRoot "config\skill_dynamic_sandbox_v2.json"
$SemanticModelConfigFile = Join-Path $DemoRoot "config\skill_semantic_model.json"
$LogRoot = Join-Path $DemoRoot "logs"
$InstallStarted = [DateTimeOffset]::Now
$ConfigChanged = $false
$ConfigExisted = $false
$ConfigBackup = $null
$DockerRepairBackups = @()
$ConfigPath = Join-Path $env:USERPROFILE ".openclaw\openclaw.json"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[Aegis] $Message" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Refresh-ProcessPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $known = @(
        (Join-Path $env:APPDATA "npm"),
        (Join-Path $env:ProgramFiles "nodejs"),
        (Join-Path $env:ProgramFiles "Git\cmd"),
        (Join-Path $env:LOCALAPPDATA "miniconda3\Scripts"),
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin"),
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin")
    )
    $entries = @($known) + @($machine -split ";") + @($user -split ";")
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $env:PATH = (@($entries | Where-Object { $_ -and $seen.Add($_) }) -join ";")
}

function Resolve-Application {
    param([string[]]$Names, [string[]]$Candidates = @())
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command -and $command.Source) { return $command.Source }
    }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$FailureMessage,
        [switch]$Capture
    )
    $priorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($Capture) {
            $lines = @(& $Command @Arguments 2>&1)
            $exitCode = $LASTEXITCODE
            $output = ($lines | Out-String).Trim()
            if ($exitCode -ne 0) { throw "$FailureMessage Exit code: $exitCode. $output" }
            return $output
        }
        & $Command @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) { throw "$FailureMessage Exit code: $exitCode" }
    } finally {
        $ErrorActionPreference = $priorPreference
    }
}

function Install-WingetPackage {
    param([string]$Id, [string]$Label)
    if ($VerifyOnly) { throw "$Label is missing; verify-only mode never installs dependencies." }
    if ($SkipDependencyInstall) { throw "$Label is missing and dependency installation was disabled." }
    $winget = Resolve-Application @("winget.exe", "winget")
    if (-not $winget) { throw "Windows Package Manager (winget) is required to install $Label." }
    Write-Step "Installing $Label through Windows Package Manager"
    Invoke-Checked $winget @(
        "install", "--id", $Id, "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements"
    ) "Failed to install $Label."
    Refresh-ProcessPath
}

function Resolve-Node {
    return Resolve-Application @("node.exe", "node") @((Join-Path $env:ProgramFiles "nodejs\node.exe"))
}

function Resolve-Npm {
    return Resolve-Application @("npm.cmd", "npm") @((Join-Path $env:ProgramFiles "nodejs\npm.cmd"))
}

function Resolve-OpenClaw {
    return Resolve-Application @("openclaw.cmd", "openclaw") @((Join-Path $env:APPDATA "npm\openclaw.cmd"))
}

function Resolve-Pnpm {
    foreach ($candidate in @(
        (Join-Path $env:APPDATA "npm\pnpm.cmd"),
        (Join-Path $env:ProgramFiles "nodejs\pnpm.cmd")
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    $command = Get-Command pnpm.cmd,pnpm -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source -and $command.Source -notmatch "[\\/]\.cache[\\/]codex-runtimes[\\/]") {
        return $command.Source
    }
    return $null
}

function Resolve-Git {
    return Resolve-Application @("git.exe", "git") @((Join-Path $env:ProgramFiles "Git\cmd\git.exe"))
}

function Resolve-Conda {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "miniconda3\Scripts\conda.exe"),
        (Join-Path $env:LOCALAPPDATA "anaconda3\Scripts\conda.exe")
    )
    if ($env:ProgramData) {
        $candidates += Join-Path $env:ProgramData "miniconda3\Scripts\conda.exe"
        $candidates += Join-Path $env:ProgramData "anaconda3\Scripts\conda.exe"
    }
    return Resolve-Application @("conda.exe", "conda") $candidates
}

function Resolve-Docker {
    return Resolve-Application @("docker.exe", "docker") @(
        (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"),
        (Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe")
    )
}

function Resolve-Ollama {
    return Resolve-Application @("ollama.exe", "ollama") @(
        (Join-Path $env:LOCALAPPDATA "Programs\Ollama\ollama.exe")
    )
}

function Invoke-DockerEngineProbe {
    param([string]$Docker, [int]$TimeoutMilliseconds = 4000)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Docker
    $startInfo.Arguments = '--context desktop-linux version --format "{{json .Server}}"'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { return [pscustomobject]@{ ready = $false; output = "process_start_failed" } }
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            return [pscustomobject]@{ ready = $false; output = "probe_timeout" }
        }
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        return [pscustomobject]@{
            ready = $process.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($stdout)
            output = $(if ($stdout) { $stdout } else { $stderr })
        }
    } finally {
        $process.Dispose()
    }
}

function Repair-KnownDockerSocketFailure {
    $errorFile = Join-Path $env:LOCALAPPDATA "Docker\backend.error.json"
    if (-not (Test-Path -LiteralPath $errorFile -PathType Leaf)) { return $false }
    $rawError = Get-Content -LiteralPath $errorFile -Raw -ErrorAction SilentlyContinue
    $knownFailure = $rawError -match "The file cannot be accessed by the system" -and
        ($rawError -match "Docker/run/dockerInference" -or $rawError -match "docker-secrets-engine/engine.sock")
    if (-not $knownFailure) { return $false }

    Write-Warning "Detected Docker Desktop's known stale Windows AF_UNIX socket failure; applying a recoverable repair."
    $dockerProcessNames = @("Docker Desktop", "com.docker.backend", "docker-desktop", "DockerCli")
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $dockerProcessNames -contains $_.ProcessName } |
        Stop-Process -Force
    Start-Sleep -Seconds 3
    $stamp = [DateTimeOffset]::Now.ToString("yyyyMMdd-HHmmss") + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)

    $settings = Join-Path $env:APPDATA "Docker\settings-store.json"
    if (Test-Path -LiteralPath $settings -PathType Leaf) {
        $settingsRoot = [IO.Path]::GetFullPath((Split-Path -Parent $settings))
        $settings = [IO.Path]::GetFullPath($settings)
        if (-not $settings.StartsWith($settingsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Docker settings path escaped the expected directory."
        }
        $backup = Join-Path $settingsRoot ("settings-store.before-aegis-socket-repair.$stamp.json")
        Copy-Item -LiteralPath $settings -Destination $backup
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
        $temporary = Join-Path $settingsRoot ("settings-store.aegis-$stamp.tmp")
        [IO.File]::WriteAllText($temporary, ($payload | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $settings -Force
        $script:DockerRepairBackups += $backup
    }

    $localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
    foreach ($relative in @("Docker\run", "docker-secrets-engine")) {
        $source = [IO.Path]::GetFullPath((Join-Path $localRoot $relative))
        if (-not $source.StartsWith($localRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Docker runtime path escaped LocalAppData."
        }
        if (-not (Test-Path -LiteralPath $source -PathType Container)) { continue }
        $unexpected = @(Get-ChildItem -LiteralPath $source -Force -ErrorAction Stop | Where-Object {
            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $_.PSIsContainer
        })
        if ($unexpected.Count -gt 0) {
            throw "Refusing Docker socket repair because $source contains non-socket content."
        }
        $safeName = ($relative -replace "[\\/]", "-") + ".aegis-stale-$stamp"
        $destination = Join-Path $localRoot $safeName
        Move-Item -LiteralPath $source -Destination $destination
        $script:DockerRepairBackups += $destination
    }
    return $true
}

function Ensure-Dependencies {
    Write-Step "Checking Windows dependencies"
    if (-not (Resolve-Node)) { Install-WingetPackage "OpenJS.NodeJS.LTS" "Node.js LTS" }
    if (-not (Resolve-Git)) { Install-WingetPackage "Git.Git" "Git" }
    if (-not (Resolve-Conda)) { Install-WingetPackage "Anaconda.Miniconda3" "Miniconda" }
    if (-not (Resolve-Docker)) { Install-WingetPackage "Docker.DockerDesktop" "Docker Desktop" }
    if (-not (Resolve-Ollama)) { Install-WingetPackage "Ollama.Ollama" "Ollama" }
    foreach ($entry in @(
        @{ Label = "Node.js"; Value = (Resolve-Node) },
        @{ Label = "Git"; Value = (Resolve-Git) },
        @{ Label = "Conda"; Value = (Resolve-Conda) },
        @{ Label = "Docker CLI"; Value = (Resolve-Docker) }
        @{ Label = "Ollama"; Value = (Resolve-Ollama) }
    )) {
        if (-not $entry.Value) { throw "$($entry.Label) is still unavailable after dependency setup. Restart Windows and run this installer again." }
        Write-Pass "$($entry.Label): $($entry.Value)"
    }
}

function Ensure-OpenClaw {
    Write-Step "Pinning OpenClaw and pnpm versions"
    $npm = Resolve-Npm
    if (-not $npm) { throw "npm is unavailable after Node.js installation." }
    $openclaw = Resolve-OpenClaw
    $actual = ""
    if ($openclaw) {
        $actual = (Invoke-Checked $openclaw @("--version") "Cannot query OpenClaw version." -Capture).Trim()
    }
    if ($actual -notmatch [regex]::Escape($ExpectedOpenClawVersion)) {
        if ($VerifyOnly) { throw "OpenClaw $ExpectedOpenClawVersion is required; current output is '$actual'." }
        Invoke-Checked $npm @("install", "--global", "openclaw@$ExpectedOpenClawVersion") "Pinned OpenClaw installation failed."
        Refresh-ProcessPath
        $openclaw = Resolve-OpenClaw
    }
    if (-not $openclaw) { throw "OpenClaw CLI was not found after installation." }
    $actual = (Invoke-Checked $openclaw @("--version") "Cannot verify OpenClaw version." -Capture).Trim()
    if ($actual -notmatch [regex]::Escape($ExpectedOpenClawVersion)) { throw "OpenClaw version mismatch: $actual" }
    Write-Pass "OpenClaw $ExpectedOpenClawVersion"

    $pnpm = Resolve-Pnpm
    $pnpmVersion = ""
    if ($pnpm) { $pnpmVersion = (Invoke-Checked $pnpm @("--version") "Cannot query pnpm version." -Capture).Trim() }
    if ($pnpmVersion -ne $ExpectedPnpmVersion) {
        if ($VerifyOnly) { throw "pnpm $ExpectedPnpmVersion is required; current version is '$pnpmVersion'." }
        Invoke-Checked $npm @("install", "--global", "pnpm@$ExpectedPnpmVersion") "Pinned pnpm installation failed."
        Refresh-ProcessPath
        $pnpm = Resolve-Pnpm
    }
    if (-not $pnpm) { throw "pnpm is unavailable after installation." }
    $pnpmVersion = (Invoke-Checked $pnpm @("--version") "Cannot verify pnpm version." -Capture).Trim()
    if ($pnpmVersion -ne $ExpectedPnpmVersion) { throw "pnpm version mismatch: $pnpmVersion" }
    Write-Pass "pnpm $ExpectedPnpmVersion"
    return $openclaw
}

function Ensure-ScannerRuntimes {
    Write-Step "Building or verifying locked Cisco scanner runtimes"
    $env:AEGIS_CONDA_COMMAND = Resolve-Conda
    $env:AEGIS_GIT_COMMAND = Resolve-Git
    $bootstrap = Join-Path $ProjectRoot "bootstrap_runtimes.ps1"
    if ($VerifyOnly) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrap -Component All -VerifyOnly
    } else {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $bootstrap -Component All
    }
    if ($LASTEXITCODE -ne 0) { throw "Locked scanner runtime bootstrap failed." }
    if (-not (Test-Path -LiteralPath $RuntimePython -PathType Leaf)) { throw "Aegis administrator runtime is missing." }
    Write-Pass "Cisco Skill Scanner, MCP Scanner, backend and security overlay are locked and verified"
}

function Ensure-DockerReady {
    Write-Step "Preparing the Docker isolation backend"
    $docker = Resolve-Docker
    if (-not $docker) { throw "Docker CLI is unavailable." }
    $probe = Invoke-DockerEngineProbe $docker
    if (-not $probe.ready) {
        if ($VerifyOnly) {
            throw "Docker Desktop Linux engine is not ready; verify-only mode never starts or repairs services. $($probe.output)"
        }
        $desktop = Resolve-Application @() @(
            (Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\Docker Desktop.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\Docker Desktop\Docker Desktop.exe")
        )
        if ($desktop) {
            Write-Host "Starting Docker Desktop and waiting for the Linux engine..."
            Start-Process -FilePath $desktop -WindowStyle Hidden | Out-Null
        }
        $ready = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            $probe = Invoke-DockerEngineProbe $docker
            if ($probe.ready) { $ready = $true; break }
        }
        if (-not $ready -and (Repair-KnownDockerSocketFailure)) {
            if ($desktop) { Start-Process -FilePath $desktop -WindowStyle Hidden | Out-Null }
            for ($attempt = 1; $attempt -le 24; $attempt++) {
                Start-Sleep -Seconds 5
                $probe = Invoke-DockerEngineProbe $docker
                if ($probe.ready) { $ready = $true; break }
            }
        }
        if (-not $ready) { throw "Docker Desktop Linux engine did not become ready within 180 seconds. Restart Windows or repair Docker Desktop, then run this installer again." }
    }
    Write-Pass "Docker Desktop Linux engine is available"

    $dockerContract = Get-Content -LiteralPath $DockerConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $uniqueImages = @($dockerContract.images.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Runtime = $_.Name; Reference = [string]$_.Value.reference; ExpectedId = [string]$_.Value.id }
    } | Group-Object Reference | ForEach-Object { $_.Group | Select-Object -First 1 })
    foreach ($image in $uniqueImages) {
        $priorPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $actualImageId = (& $docker --context desktop-linux image inspect $image.Reference --format "{{json .Id}}" 2>$null | Out-String).Trim('"', "`r", "`n", " ")
            $imageExit = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $priorPreference
        }
        if ($imageExit -ne 0 -or $actualImageId -ne $image.ExpectedId) {
            if ($VerifyOnly) { throw "The pinned Docker image is missing or mismatched: $($image.Reference)" }
            Invoke-Checked $docker @("--context", "desktop-linux", "pull", $image.Reference) "Pinned Docker image pull failed."
            $actualImageId = (& $docker --context desktop-linux image inspect $image.Reference --format "{{json .Id}}" 2>&1 | Out-String).Trim('"', "`r", "`n", " ")
        }
        if ($actualImageId -ne $image.ExpectedId) { throw "Pinned Docker image identity mismatch. Expected $($image.ExpectedId); actual $actualImageId" }
        Write-Pass "Pinned $($image.Runtime) image identity: $actualImageId"
    }
    return $docker
}

function Ensure-SemanticModel {
    Write-Step "Preparing the local semantic review model"
    $ollama = Resolve-Ollama
    if (-not $ollama) { throw "Ollama is unavailable." }
    $contract = Get-Content -LiteralPath $SemanticModelConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $model = [string]$contract.local.model
    if ([string]::IsNullOrWhiteSpace($model)) { throw "Local semantic model configuration is invalid." }
    $installed = $false
    try {
        $tags = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 5
        $installed = @($tags.models | ForEach-Object { [string]$_.name }) -contains $model
    } catch {
        if ($VerifyOnly) {
            throw "Ollama is not responding; verify-only mode never starts the service."
        }
        Start-Process -FilePath $ollama -ArgumentList @("serve") -WindowStyle Hidden | Out-Null
        Start-Sleep -Seconds 5
    }
    if (-not $installed) {
        if ($VerifyOnly) { throw "The local semantic model is missing: $model" }
        Invoke-Checked $ollama @("pull", $model) "Local semantic model download failed."
    }
    $tags = Invoke-RestMethod -Uri "http://127.0.0.1:11434/api/tags" -TimeoutSec 10
    if (@($tags.models | ForEach-Object { [string]$_.name }) -notcontains $model) {
        throw "The local semantic model could not be verified: $model"
    }
    Write-Pass "Local semantic model: $model"
}

function New-InstallPolicyBatch {
    param([string]$Docker)
    New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
    $dockerDirectory = Split-Path -Parent $Docker
    $environmentPath = @($dockerDirectory, (Join-Path $env:WINDIR "System32"), $env:WINDIR) -join ";"
    $value = [ordered]@{
        enabled = $true
        targets = @("skill", "plugin")
        exec = [ordered]@{
            source = "exec"
            command = $RuntimePython
            args = @($InstallPolicyScript)
            timeoutMs = 135000
            noOutputTimeoutMs = 135000
            maxOutputBytes = 1048576
            env = [ordered]@{
                AEGIS_OPENCLAW_SCAN_TIMEOUT_SECONDS = "60"
                AEGIS_OPENCLAW_REVIEW_MODE = "block"
                AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY = "required"
                AEGIS_SEMANTIC_MODEL_MODE = "local"
                AEGIS_EXTERNAL_LLM_OPT_IN = "0"
                AEGIS_OPENCLAW_AUDIT_DB = $AuditDb
                AEGIS_CUSTOM_RULES_PATH = $CustomRules
                DOCKER_CONFIG = (Join-Path $env:USERPROFILE ".docker")
                PYTHONUTF8 = "1"
                PYTHONIOENCODING = "utf-8"
                SYSTEMROOT = $env:SystemRoot
                WINDIR = $env:WINDIR
                PATHEXT = ".COM;.EXE;.BAT;.CMD"
                LOCALAPPDATA = $env:LOCALAPPDATA
                ProgramFiles = $env:ProgramFiles
                PATH = $environmentPath
            }
            passEnv = @()
            trustedDirs = @((Split-Path -Parent $RuntimePython), (Split-Path -Parent $InstallPolicyScript))
            # OpenClaw 2026.7.1-2 reports Windows ACL inspection as unavailable.
            # The bypass is therefore paired with exact absolute paths and the
            # smallest possible trusted directory list.
            allowInsecurePath = $true
        }
    }
    $batch = @(
        [ordered]@{ path = "gateway.mode"; value = "local" },
        [ordered]@{ path = "gateway.bind"; value = "loopback" },
        [ordered]@{ path = "gateway.port"; value = $GatewayPort },
        [ordered]@{ path = "security.installPolicy"; value = $value }
    )
    $batchPath = Join-Path $DataRoot ("config-set." + [Guid]::NewGuid().ToString("N") + ".json")
    [IO.File]::WriteAllText($batchPath, ($batch | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    return $batchPath
}

function Backup-OpenClawConfig {
    $script:ConfigExisted = Test-Path -LiteralPath $ConfigPath -PathType Leaf
    if (-not $ConfigExisted) { return }
    $backupRoot = Join-Path (Split-Path -Parent $ConfigPath) "aegis-backups"
    New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null
    $script:ConfigBackup = Join-Path $backupRoot ("openclaw.before-aegis." + [DateTimeOffset]::Now.ToString("yyyyMMdd-HHmmss") + ".json")
    Copy-Item -LiteralPath $ConfigPath -Destination $ConfigBackup
    Write-Pass "OpenClaw configuration backup: $ConfigBackup"
}

function Configure-OpenClaw {
    param([string]$OpenClaw, [string]$Docker)
    Write-Step $(if ($VerifyOnly) { "Verifying the fail-closed installation policy" } else { "Applying the fail-closed installation policy" })
    if ($VerifyOnly) {
        $raw = Invoke-Checked $OpenClaw @("config", "get", "security.installPolicy", "--json") "Cannot read OpenClaw installation policy." -Capture
        $current = $raw | ConvertFrom-Json
        if (-not $current.enabled -or @($current.targets) -notcontains "skill" -or @($current.targets) -notcontains "plugin") {
            throw "OpenClaw installation policy is not enabled for both Skill and Plugin."
        }
        if ([string]$current.exec.command -ne $RuntimePython -or @($current.exec.args) -notcontains $InstallPolicyScript) {
            throw "OpenClaw installation policy does not point to this Aegis project."
        }
        Write-Pass "Existing OpenClaw installation policy points to this project"
        return
    }
    Backup-OpenClawConfig
    $batchPath = New-InstallPolicyBatch $Docker
    try {
        Invoke-Checked $OpenClaw @("config", "set", "--batch-file", $batchPath, "--dry-run", "--replace") "OpenClaw policy dry-run failed."
        Invoke-Checked $OpenClaw @("config", "set", "--batch-file", $batchPath, "--replace") "OpenClaw policy update failed."
        $script:ConfigChanged = $true
    } finally {
        if (Test-Path -LiteralPath $batchPath) { Remove-Item -LiteralPath $batchPath -Force }
    }
    Write-Pass "Skill and Plugin installation admission is enabled; MCP admission is exposed through the Aegis Security Center"
}

function Install-AegisPlugin {
    param([string]$OpenClaw)
    Write-Step $(if ($VerifyOnly) { "Verifying the Aegis Control UI registration" } else { "Installing the Aegis Control UI through the active policy" })
    if ($VerifyOnly) {
        $plugins = Invoke-Checked $OpenClaw @("plugins", "list", "--json") "Cannot inspect OpenClaw plugins." -Capture
        if ($plugins -notmatch 'aegis-admission-ui') { throw "Aegis plugin is not installed." }
        Write-Pass "Aegis plugin is registered"
        return
    }
    Invoke-Checked $OpenClaw @("plugins", "install", "--link", $PluginRoot) "Aegis plugin installation was rejected or failed."
    Invoke-Checked $OpenClaw @("plugins", "enable", "aegis-admission-ui") "Aegis plugin could not be enabled."
    Write-Pass "Aegis plugin passed installation policy and is enabled"
}

function Start-AndVerifyGateway {
    param([string]$OpenClaw)
    Write-Step $(if ($VerifyOnly) { "Verifying the running OpenClaw gateway" } else { "Installing and restarting the local OpenClaw gateway" })
    if (-not $VerifyOnly) {
        Invoke-Checked $OpenClaw @("gateway", "install", "--force", "--port", [string]$GatewayPort) "OpenClaw gateway service installation failed."
        Invoke-Checked $OpenClaw @("gateway", "restart") "OpenClaw gateway restart failed."
    }
    $base = "http://127.0.0.1:$GatewayPort"
    $ready = $false
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "$base/plugins/aegis-security-center/panel" -TimeoutSec 5
            if ([int]$response.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Seconds 5
    }
    if (-not $ready) { throw "OpenClaw gateway or Aegis plugin did not become ready within 120 seconds." }
    foreach ($route in @(
        "/plugins/aegis-security-center/panel",
        "/plugins/aegis-admission/panel?embed=1",
        "/plugins/aegis-admin/reports?embed=1",
        "/plugins/aegis-admin/audit?embed=1",
        "/plugins/aegis-admin/rules?embed=1",
        "/plugins/aegis-admin/mcp?embed=1"
    )) {
        $response = Invoke-WebRequest -UseBasicParsing -Uri ($base + $route) -TimeoutSec 15
        if ([int]$response.StatusCode -ne 200) { throw "Control UI route failed: $route" }
    }
    Write-Pass "The unified Aegis Security Center and all five feature views returned HTTP 200"
}

function Invoke-FinalPreflight {
    Write-Step "Running full platform preflight"
    $env:AEGIS_ADMIN_TOKEN = ([Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N"))
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $DemoRoot "preflight.ps1") -RequireDynamic
    if ($LASTEXITCODE -ne 0) { throw "Full Aegis platform preflight failed." }
    Write-Pass "Static scanners, Docker isolation, policy and locked dependencies passed preflight"
}

function Write-InstallationReceipt {
    param([string]$OpenClaw, [string]$Docker)
    $receipt = [ordered]@{
        schema_version = "1.0"
        installed_at = [DateTimeOffset]::Now.ToString("o")
        project_root = $ProjectRoot
        openclaw_version = $ExpectedOpenClawVersion
        gateway_url = "http://127.0.0.1:$GatewayPort/"
        plugin_id = "aegis-admission-ui"
        install_policy_targets = @("skill", "plugin")
        mcp_admission = "Aegis Security Center MCP tab; official openclaw mcp set/show commit and verification"
        dynamic_skill_policy = "required"
        audit_database = $AuditDb
        custom_rule_registry = $CustomRules
        docker_cli = $Docker
        docker_repair_backups = @($DockerRepairBackups)
        config_backup = $ConfigBackup
        control_ui_sidebar_entries = 1
        control_ui_routes_verified = 6
        status = "ready"
    }
    $receiptPath = Join-Path $DataRoot "installation_receipt.json"
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Pass "Installation receipt: $receiptPath"
}

function Restore-ConfigAfterFailure {
    if (-not $ConfigChanged) { return }
    try {
        if ($ConfigExisted -and $ConfigBackup -and (Test-Path -LiteralPath $ConfigBackup -PathType Leaf)) {
            Copy-Item -LiteralPath $ConfigBackup -Destination $ConfigPath -Force
            Write-Warning "Installation failed after configuration changed; the original OpenClaw configuration was restored."
        } elseif (-not $ConfigExisted -and (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            Remove-Item -LiteralPath $ConfigPath -Force
            Write-Warning "Installation failed after creating a new OpenClaw configuration; the generated configuration was removed."
        }
    } catch {
        Write-Warning "Automatic configuration rollback failed: $($_.Exception.Message). Backup: $ConfigBackup"
    }
}

if (-not $env:USERPROFILE -or -not $env:APPDATA -or -not $env:LOCALAPPDATA -or -not $env:ProgramFiles -or -not $env:WINDIR) {
    throw "Required Windows user environment variables are unavailable."
}
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot "bootstrap_runtimes.ps1") -PathType Leaf) -or
    -not (Test-Path -LiteralPath $PluginRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $InstallPolicyScript -PathType Leaf)) {
    throw "This installer must remain in the Aegis Chain project root."
}

New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
$transcript = Join-Path $LogRoot ("install-openclaw-final-" + [DateTimeOffset]::Now.ToString("yyyyMMdd-HHmmss") + ".log")
Start-Transcript -LiteralPath $transcript | Out-Null
try {
    Write-Host "Aegis Chain + OpenClaw Windows final installer" -ForegroundColor White
    Write-Host "Project: $ProjectRoot"
    Write-Host "Mode: $(if ($VerifyOnly) { 'verify only' } else { 'install / repair' })"
    Refresh-ProcessPath
    Ensure-Dependencies
    $openclaw = Ensure-OpenClaw
    Ensure-ScannerRuntimes
    $docker = Ensure-DockerReady
    Ensure-SemanticModel
    Configure-OpenClaw $openclaw $docker
    Install-AegisPlugin $openclaw
    Start-AndVerifyGateway $openclaw
    Invoke-FinalPreflight
    if (-not $VerifyOnly) { Write-InstallationReceipt $openclaw $docker }
    Write-Host "`nAegis Chain final integration is READY." -ForegroundColor Green
    Write-Host "OpenClaw: http://127.0.0.1:$GatewayPort/"
    Write-Host "Install log: $transcript"
    if (-not $NoLaunch) { Start-Process "http://127.0.0.1:$GatewayPort/plugin?plugin=aegis-admission-ui&id=admission" | Out-Null }
} catch {
    Restore-ConfigAfterFailure
    Write-Error $_.Exception.Message
    Write-Host "Install log: $transcript" -ForegroundColor Yellow
    exit 1
} finally {
    Stop-Transcript | Out-Null
}

exit 0
