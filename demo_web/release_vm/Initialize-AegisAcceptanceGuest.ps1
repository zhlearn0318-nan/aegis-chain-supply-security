[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit,
    [string]$RepositoryUrl = "https://github.com/zhlearn0318-nan/aegis-chain-supply-security.git",
    [string]$ExpectedRef = "refs/heads/dynamic-audit-v1",
    [string]$WorkspaceRoot = "C:\AegisAcceptance",
    [string]$GitHubTokenEnvironment = "AEGIS_GITHUB_READ_TOKEN",
    [string]$ProxyUrl = "",
    [switch]$PrepareOnly
)

$ErrorActionPreference = "Stop"
$ControllerRoot = $PSScriptRoot
$ToolchainManifest = Join-Path $ControllerRoot "toolchain.windows-x64.json"
$ControllerPath = $MyInvocation.MyCommand.Path
$ExpectedCommit = $ExpectedCommit.ToLowerInvariant()
$DownloadProxyUrl = $null
if (-not [string]::IsNullOrWhiteSpace($ProxyUrl)) {
    try { $proxy = [Uri]$ProxyUrl } catch { throw "ProxyUrl is not a valid absolute URI." }
    if (
        -not $proxy.IsAbsoluteUri -or
        $proxy.Scheme -notin @("http", "https") -or
        [string]::IsNullOrWhiteSpace($proxy.Host) -or
        $proxy.IsDefaultPort -or
        -not [string]::IsNullOrWhiteSpace($proxy.UserInfo) -or
        $proxy.AbsolutePath -ne "/" -or
        $proxy.Query -or
        $proxy.Fragment
    ) {
        throw "ProxyUrl must be an explicit HTTP(S) host and port without credentials, path, query, or fragment."
    }
    $DownloadProxyUrl = $proxy.AbsoluteUri.TrimEnd("/")
    $env:HTTP_PROXY = $DownloadProxyUrl
    $env:HTTPS_PROXY = $DownloadProxyUrl
    $env:ALL_PROXY = $DownloadProxyUrl
    $env:NO_PROXY = "127.0.0.1,localhost,::1"
}

function Write-Utf8Json {
    param([string]$Path, $Value)
    $json = $Value | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText($Path, $json + "`n", [Text.UTF8Encoding]::new($false))
}

function Get-NormalizedTextSha256 {
    param([string]$Path)
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8).Replace("`r`n", "`n").Replace("`r", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

function Get-VerifiedDownload {
    param($Artifact, [string]$DownloadRoot)
    $target = Join-Path $DownloadRoot ([string]$Artifact.file)
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Write-Host "Downloading locked $($Artifact.id) $($Artifact.version)..."
        $download = @{
            UseBasicParsing = $true
            Uri = [string]$Artifact.url
            OutFile = $target
        }
        if ($DownloadProxyUrl) { $download.Proxy = $DownloadProxyUrl }
        Invoke-WebRequest @download
    }
    $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne ([string]$Artifact.sha256).ToLowerInvariant()) {
        throw "SHA-256 mismatch for $($Artifact.file). Expected $($Artifact.sha256); actual $actual."
    }
    return [pscustomobject]@{
        id = [string]$Artifact.id
        version = [string]$Artifact.version
        file = [string]$Artifact.file
        path = $target
        url = [string]$Artifact.url
        sha256 = $actual
        runtime_version = [string]$Artifact.runtime_version
        license = [string]$Artifact.license
        verified = $true
    }
}

function Get-VerifiedIntegrityDownload {
    param($Package, [string]$DownloadRoot)
    $target = Join-Path $DownloadRoot ([string]$Package.file)
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Write-Host "Downloading locked $($Package.id) $($Package.version)..."
        $download = @{
            UseBasicParsing = $true
            Uri = [string]$Package.tarball
            OutFile = $target
        }
        if ($DownloadProxyUrl) { $download.Proxy = $DownloadProxyUrl }
        Invoke-WebRequest @download
    }
    $expected = [string]$Package.integrity
    $parts = $expected -split '-', 2
    if ($parts.Count -ne 2 -or $parts[0] -cne "sha512") {
        throw "Unsupported package integrity for $($Package.id): $expected"
    }
    $stream = [IO.File]::OpenRead($target)
    $sha = [Security.Cryptography.SHA512]::Create()
    try {
        $actual = "sha512-" + [Convert]::ToBase64String($sha.ComputeHash($stream))
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
    if ($actual -cne $expected) {
        throw "SRI mismatch for $($Package.file)."
    }
    return [pscustomobject]@{
        id = [string]$Package.id
        version = [string]$Package.version
        file = [string]$Package.file
        path = $target
        url = [string]$Package.tarball
        integrity = $actual
        license = [string]$Package.license
        verified = $true
    }
}

function Get-VirtualMachineEvidence {
    try {
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    } catch {
        throw "Cannot collect the hardware identity required to prove a real Windows VM: $($_.Exception.Message)"
    }
    $combined = @(
        [string]$computer.Manufacturer,
        [string]$computer.Model,
        [string]$bios.Manufacturer,
        [string]$bios.SMBIOSBIOSVersion,
        [string]$baseboard.Manufacturer,
        [string]$baseboard.Product
    ) -join " | "
    $provider = switch -Regex ($combined) {
        'VirtualBox|innotek|Oracle.*Virtual' { "virtualbox"; break }
        'VMware' { "vmware"; break }
        'KVM|QEMU|Bochs' { "qemu-kvm"; break }
        'Parallels' { "parallels"; break }
        'Xen' { "xen"; break }
        'Microsoft Corporation.*Virtual Machine|Hyper-V|Windows Sandbox' { "hyper-v-or-windows-sandbox"; break }
        default { "unproved" }
    }
    if ($provider -eq "unproved") {
        throw "The machine identity does not prove a supported real VM. Physical-host or directory simulation is rejected. Observed: $combined"
    }
    $machineGuid = [string](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $machineHash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid)))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    return [pscustomobject]@{
        proof_accepted = $true
        provider = $provider
        manufacturer = [string]$computer.Manufacturer
        model = [string]$computer.Model
        bios_manufacturer = [string]$bios.Manufacturer
        bios_version = [string]$bios.SMBIOSBIOSVersion
        baseboard_manufacturer = [string]$baseboard.Manufacturer
        baseboard_product = [string]$baseboard.Product
        hypervisor_present = [bool]$computer.HypervisorPresent
        logical_processors = [int]$computer.NumberOfLogicalProcessors
        memory_bytes = [uint64]$computer.TotalPhysicalMemory
        machine_guid_sha256 = $machineHash
    }
}

if (-not (Test-Path -LiteralPath $ToolchainManifest -PathType Leaf)) {
    throw "Missing toolchain manifest: $ToolchainManifest"
}
$manifest = Get-Content -LiteralPath $ToolchainManifest -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema_version -ne "1.0" -or $manifest.platform -ne "windows-x64") {
    throw "Unsupported clean-VM toolchain manifest."
}
$vm = Get-VirtualMachineEvidence
$workspace = [IO.Path]::GetFullPath($WorkspaceRoot)
$downloads = Join-Path $workspace "downloads"
$toolsRoot = Join-Path $workspace "tools"
$repository = Join-Path $workspace "repository"
$evidence = Join-Path $workspace "evidence"
if (Test-Path -LiteralPath $repository) {
    throw "Fresh-clone target already exists and will not be reused: $repository"
}
New-Item -ItemType Directory -Force -Path $downloads, $toolsRoot, $evidence | Out-Null

$verified = @{}
foreach ($artifact in $manifest.artifacts) {
    $verified[$artifact.id] = Get-VerifiedDownload $artifact $downloads
}
$pnpmPackage = @($manifest.package_managers | Where-Object { $_.id -eq "pnpm" })
if ($pnpmPackage.Count -ne 1) {
    throw "The toolchain manifest must contain exactly one pnpm package manager entry."
}
$verified["pnpm"] = Get-VerifiedIntegrityDownload $pnpmPackage[0] $downloads

$mingitRoot = Join-Path $toolsRoot "mingit-2.53.0.3"
if (-not (Test-Path -LiteralPath (Join-Path $mingitRoot "cmd\git.exe") -PathType Leaf)) {
    if (Test-Path -LiteralPath $mingitRoot) {
        throw "Incomplete MinGit directory already exists: $mingitRoot"
    }
    Expand-Archive -LiteralPath $verified.mingit.path -DestinationPath $mingitRoot
}
$git = Join-Path $mingitRoot "cmd\git.exe"

$nodeRoot = Join-Path $toolsRoot "node-v24.15.0-win-x64"
if (-not (Test-Path -LiteralPath (Join-Path $nodeRoot "node.exe") -PathType Leaf)) {
    if (Test-Path -LiteralPath $nodeRoot) {
        throw "Incomplete Node.js directory already exists: $nodeRoot"
    }
    Expand-Archive -LiteralPath $verified.node.path -DestinationPath $toolsRoot
}
$node = Join-Path $nodeRoot "node.exe"

$miniforgeRoot = Join-Path $toolsRoot "miniforge3-25.11.0-1"
$conda = Join-Path $miniforgeRoot "Scripts\conda.exe"
if (-not (Test-Path -LiteralPath $conda -PathType Leaf)) {
    if (Test-Path -LiteralPath $miniforgeRoot) {
        throw "Incomplete Miniforge directory already exists: $miniforgeRoot"
    }
    $installerArguments = @(
        "/InstallationType=JustMe",
        "/RegisterPython=0",
        "/AddToPath=0",
        "/S",
        "/D=$miniforgeRoot"
    )
    $process = Start-Process -FilePath $verified.miniforge.path -ArgumentList $installerArguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $conda -PathType Leaf)) {
        throw "Locked Miniforge installation failed with exit code $($process.ExitCode)."
    }
}

$env:PATH = @($nodeRoot, (Join-Path $mingitRoot "cmd"), (Join-Path $mingitRoot "mingw64\bin"), (Join-Path $miniforgeRoot "Scripts"), $env:PATH) -join ";"
$tar = Join-Path $env:SystemRoot "System32\tar.exe"
if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) {
    throw "Windows tar.exe is required to unpack the integrity-verified pnpm package."
}
$pnpmRoot = Join-Path $toolsRoot "pnpm-11.19.0"
$pnpmCli = Join-Path $pnpmRoot "package\bin\pnpm.cjs"
$pnpm = Join-Path $pnpmRoot "pnpm.cmd"
if (-not (Test-Path -LiteralPath $pnpmCli -PathType Leaf)) {
    if (Test-Path -LiteralPath $pnpmRoot) {
        throw "Incomplete pnpm directory already exists: $pnpmRoot"
    }
    New-Item -ItemType Directory -Path $pnpmRoot | Out-Null
    Invoke-Checked $tar @("-xf", $verified.pnpm.path, "-C", $pnpmRoot) "Verified pnpm extraction"
}
if (-not (Test-Path -LiteralPath $pnpm -PathType Leaf)) {
    $pnpmBody = "@echo off`r`n`"$node`" `"$pnpmCli`" %*`r`n"
    [IO.File]::WriteAllText($pnpm, $pnpmBody, [Text.Encoding]::ASCII)
}
if (-not (Test-Path -LiteralPath $pnpm -PathType Leaf)) {
    throw "The verified pnpm package did not produce a runnable shim."
}

$actualGit = (& $git --version 2>&1 | Out-String).Trim()
$actualNode = (& $node --version 2>&1 | Out-String).Trim().TrimStart("v")
$actualConda = (& $conda --version 2>&1 | Out-String).Trim()
$actualPnpm = (& $pnpm --version 2>&1 | Out-String).Trim()
if (
    $actualGit -notmatch '2\.53\.0\.windows\.3' -or
    $actualNode -ne "24.15.0" -or
    $actualConda -ne "conda $($verified.miniforge.runtime_version)" -or
    $actualPnpm -ne "11.19.0"
) {
    throw "Toolchain version verification failed: $actualGit / Node $actualNode / $actualConda / pnpm $actualPnpm."
}

$token = [Environment]::GetEnvironmentVariable($GitHubTokenEnvironment, "Process")
$askPass = $null
$oldAskPass = $env:GIT_ASKPASS
$oldTerminalPrompt = $env:GIT_TERMINAL_PROMPT
if (-not [string]::IsNullOrWhiteSpace($token)) {
    $askPass = Join-Path $workspace "git-askpass.cmd"
    $askPassBody = @"
@echo off
echo %~1 | findstr /I "username" >nul
if %errorlevel%==0 (echo x-access-token) else (echo %$GitHubTokenEnvironment%)
"@
    [IO.File]::WriteAllText($askPass, $askPassBody, [Text.Encoding]::ASCII)
    $env:GIT_ASKPASS = $askPass
    $env:GIT_TERMINAL_PROMPT = "0"
}

$cloneStarted = [DateTimeOffset]::UtcNow
try {
    $remoteText = (& $git ls-remote $RepositoryUrl $ExpectedRef 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Remote reference lookup failed: $remoteText" }
    $remoteCommit = (($remoteText -split "\s+")[0]).ToLowerInvariant()
    if ($remoteCommit -ne $ExpectedCommit) {
        throw "Remote $ExpectedRef is $remoteCommit, not expected $ExpectedCommit."
    }
    Invoke-Checked $git @("clone", "--no-checkout", "--single-branch", "--branch", ($ExpectedRef -replace '^refs/heads/', ''), $RepositoryUrl, $repository) "Fresh remote clone"
    Invoke-Checked $git @("-C", $repository, "checkout", "--detach", $ExpectedCommit) "Expected commit checkout"
} finally {
    if ($askPass -and (Test-Path -LiteralPath $askPass)) {
        Remove-Item -LiteralPath $askPass -Force
    }
    $env:GIT_ASKPASS = $oldAskPass
    $env:GIT_TERMINAL_PROMPT = $oldTerminalPrompt
}
$cloneCompleted = [DateTimeOffset]::UtcNow
$actualCommit = (& $git -C $repository rev-parse HEAD 2>&1 | Out-String).Trim().ToLowerInvariant()
$actualOrigin = (& $git -C $repository remote get-url origin 2>&1 | Out-String).Trim()
$initialStatus = (& $git -C $repository status --porcelain=v1 --untracked-files=all 2>&1 | Out-String).Trim()
if ($actualCommit -ne $ExpectedCommit -or $actualOrigin -ne $RepositoryUrl -or $initialStatus) {
    throw "Fresh-clone provenance verification failed."
}
$generatedPaths = @(
    ".runtime_skill",
    ".runtime_mcp313",
    "third_party\skill-scanner",
    "third_party\mcp-scanner",
    "demo_web\frontend\node_modules",
    "demo_web\data\scan_history.db"
)
$preexistingGenerated = @($generatedPaths | Where-Object { Test-Path -LiteralPath (Join-Path $repository $_) })
if ($preexistingGenerated.Count -ne 0) {
    throw "Fresh clone unexpectedly contains generated runtime paths: $($preexistingGenerated -join ', ')"
}

$preflightPath = Join-Path $repository "demo_web\preflight.ps1"
$preflightText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $preflightPath -SkipDynamic -Json 2>&1 | Out-String).Trim()
$preflightExit = $LASTEXITCODE
try { $preflight = $preflightText | ConvertFrom-Json } catch { throw "Pre-bootstrap preflight did not return JSON: $preflightText" }
if ($preflightExit -eq 0 -or $preflight.ready -ne $false -or [int]$preflight.required_failures -lt 1) {
    throw "Pre-bootstrap negative control did not prove missing clean-VM runtimes."
}

$attestationPath = Join-Path $evidence "fresh_clone_attestation.json"
$attestation = [ordered]@{
    schema_version = "1.0"
    status = "completed"
    virtual_machine = $vm
    toolchain_manifest_sha256 = Get-NormalizedTextSha256 $ToolchainManifest
    controller_sha256 = Get-NormalizedTextSha256 $ControllerPath
    toolchain = [ordered]@{
        downloads = @($verified.Values | Sort-Object id)
        git = [ordered]@{ version = $actualGit; path = $git }
        node = [ordered]@{ version = $actualNode; path = $node }
        conda = [ordered]@{ version = $actualConda; path = $conda }
        pnpm = [ordered]@{ version = $actualPnpm; path = $pnpm; integrity = $manifest.package_managers[0].integrity }
    }
    repository = [ordered]@{
        fresh_clone = $true
        target_preexisted = $false
        url = $actualOrigin
        ref = $ExpectedRef
        remote_commit = $remoteCommit
        checkout_commit = $actualCommit
        initial_status = $initialStatus
        preexisting_generated_paths = $preexistingGenerated
        clone_started_at = $cloneStarted.ToString("o")
        clone_completed_at = $cloneCompleted.ToString("o")
        path = $repository
    }
    negative_control = [ordered]@{
        prebootstrap_preflight_exit = $preflightExit
        prebootstrap_required_failures = [int]$preflight.required_failures
        prebootstrap_ready = [bool]$preflight.ready
        output = $preflight
    }
    sensitive_values = [ordered]@{
        github_token_environment = $GitHubTokenEnvironment
        github_token_retained = $false
        proxy_credentials_allowed = $false
    }
    network = [ordered]@{ proxy_configured = [bool]$DownloadProxyUrl }
}
Write-Utf8Json $attestationPath $attestation

$env:AEGIS_GIT_COMMAND = $git
$env:AEGIS_CONDA_COMMAND = $conda
$env:AEGIS_PNPM_COMMAND = $pnpm
Write-Host "PASS real VM, locked toolchain, remote ref, fresh clone, and negative preflight were verified."
Write-Host "Repository: $repository"
Write-Host "Attestation: $attestationPath"
if ($PrepareOnly) { exit 0 }

$gate = Join-Path $repository "demo_web\release_vm\Invoke-AegisReleaseAcceptance.ps1"
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $gate -ExpectedCommit $ExpectedCommit -ExpectedRef $ExpectedRef -RepositoryUrl $RepositoryUrl -AttestationPath $attestationPath -EvidenceRoot $evidence
exit $LASTEXITCODE
