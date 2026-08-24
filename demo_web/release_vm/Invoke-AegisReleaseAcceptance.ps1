[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedCommit,
    [Parameter(Mandatory = $true)][string]$AttestationPath,
    [Parameter(Mandatory = $true)][string]$EvidenceRoot,
    [string]$ExpectedRef = "refs/heads/dynamic-audit-v1",
    [string]$RepositoryUrl = "https://github.com/zhlearn0318-nan/aegis-chain-supply-security.git",
    [string]$RunId = "2026-08-25-clean-windows-vm-release-v1",
    [ValidateRange(1024, 65534)][int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$DemoRoot = Split-Path $PSScriptRoot -Parent
$ProjectRoot = Split-Path $DemoRoot -Parent
$ExpectedCommit = $ExpectedCommit.ToLowerInvariant()
$EvidenceRoot = [IO.Path]::GetFullPath($EvidenceRoot)
$AttestationPath = [IO.Path]::GetFullPath($AttestationPath)
$ProjectRootFull = [IO.Path]::GetFullPath($ProjectRoot)
$StartedAt = [DateTimeOffset]::UtcNow
$Stopwatch = [Diagnostics.Stopwatch]::StartNew()
$ServerStarted = $false
$OfflineServerStarted = $false
$PriorEnvironment = @{}

function Write-Utf8Text {
    param([string]$Path, [string]$Value)
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Write-Utf8Json {
    param([string]$Path, $Value)
    Write-Utf8Text $Path (($Value | ConvertTo-Json -Depth 30) + "`n")
}

function Invoke-LoggedStep {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $ProjectRoot,
        [switch]$AllowFailure
    )
    $stepStart = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $prior = Get-Location
    $priorErrorActionPreference = $ErrorActionPreference
    try {
        Set-Location -LiteralPath $WorkingDirectory
        # Windows PowerShell 5.1 wraps native stderr as ErrorRecord objects. With the
        # script-wide Stop policy those records terminate this collector before the
        # native process exit code and useful stderr can be persisted. Continue only
        # inside the collector; the explicit exit-code gate below remains fail closed.
        $ErrorActionPreference = "Continue"
        $records = @(& $Command @Arguments 2>&1)
        $output = ($records | ForEach-Object {
            if ($_ -is [Management.Automation.ErrorRecord]) {
                $text = $_.ToString()
                $exceptionText = if ($_.Exception) { $_.Exception.ToString() } else { "" }
                if ($exceptionText -and $exceptionText -ne $text) {
                    $text + "`n" + $exceptionText
                } else {
                    $text
                }
            } else {
                $_.ToString()
            }
        }) -join "`n"
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    } catch {
        $output = (@($_.ToString(), $_.Exception.ToString()) | Select-Object -Unique) -join "`n"
        $exitCode = 1
    } finally {
        $ErrorActionPreference = $priorErrorActionPreference
        Set-Location -LiteralPath $prior
        $timer.Stop()
    }
    $logPath = Join-Path $EvidenceRoot ($Id + ".log")
    Write-Utf8Text $logPath ($output.TrimEnd() + "`n")
    $row = [pscustomobject]@{
        id = $Id
        command = $Command
        arguments = $Arguments
        started_at = $stepStart.ToString("o")
        duration_ms = [int]$timer.ElapsedMilliseconds
        exit_code = [int]$exitCode
        log = [IO.Path]::GetFileName($logPath)
    }
    Write-Utf8Json (Join-Path $EvidenceRoot ($Id + ".step.json")) $row
    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "$Id failed with exit code $exitCode. See $logPath"
    }
    return [pscustomobject]@{ metadata = $row; output = $output; exit_code = $exitCode }
}

function Stop-AegisServer {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $DemoRoot "stop_demo.ps1") 2>&1 | Out-Null
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        $offlineListener = Get-NetTCPConnection -LocalPort ($Port + 1) -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $listener -and -not $offlineListener) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Aegis server listener remained after stop."
}

function Copy-ServerLogs {
    param([string]$Prefix)
    $logRoot = Join-Path $DemoRoot "logs"
    foreach ($name in @("server.out.log", "server.err.log")) {
        $source = Join-Path $logRoot $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $EvidenceRoot ($Prefix + "-" + $name))
        }
    }
}

if ($EvidenceRoot.StartsWith($ProjectRootFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Release evidence must be written outside the fresh clone."
}
if (-not (Test-Path -LiteralPath $AttestationPath -PathType Leaf)) {
    throw "Fresh-clone VM attestation is missing: $AttestationPath"
}
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$protected = @("run_manifest.json", "metrics.json", "summary.md", "claim_validation.md", "artifact_manifest.json", "failure.json")
$existing = @($protected | Where-Object { Test-Path -LiteralPath (Join-Path $EvidenceRoot $_) })
if ($existing.Count -gt 0) {
    throw "Refusing to overwrite release evidence: $($existing -join ', ')"
}

$attestation = Get-Content -LiteralPath $AttestationPath -Raw -Encoding UTF8 | ConvertFrom-Json
$allowedProviders = @("virtualbox", "vmware", "qemu-kvm", "parallels", "xen", "hyper-v-or-windows-sandbox")
if (
    $attestation.status -ne "completed" -or
    $attestation.virtual_machine.proof_accepted -ne $true -or
    $allowedProviders -notcontains [string]$attestation.virtual_machine.provider -or
    ([string]$attestation.repository.checkout_commit).ToLowerInvariant() -ne $ExpectedCommit -or
    $attestation.repository.fresh_clone -ne $true
) {
    throw "The supplied attestation does not prove the expected real VM fresh clone."
}

$requiredEnvironment = @("AEGIS_GIT_COMMAND", "AEGIS_CONDA_COMMAND", "AEGIS_PNPM_COMMAND")
foreach ($name in $requiredEnvironment) {
    $value = [Environment]::GetEnvironmentVariable($name, "Process")
    if (-not $value -or -not (Test-Path -LiteralPath $value -PathType Leaf)) {
        throw "$name is missing; run Initialize-AegisAcceptanceGuest.ps1 in the VM."
    }
}
$Git = $env:AEGIS_GIT_COMMAND
$Conda = $env:AEGIS_CONDA_COMMAND
$Pnpm = $env:AEGIS_PNPM_COMMAND
$currentCommit = (& $Git -C $ProjectRoot rev-parse HEAD 2>&1 | Out-String).Trim().ToLowerInvariant()
$currentOrigin = (& $Git -C $ProjectRoot remote get-url origin 2>&1 | Out-String).Trim()
$currentStatus = (& $Git -C $ProjectRoot status --porcelain=v1 --untracked-files=no 2>&1 | Out-String).Trim()
if ($currentCommit -ne $ExpectedCommit -or $currentOrigin -ne $RepositoryUrl -or $currentStatus) {
    throw "Repository no longer matches the attested clean checkout."
}

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $tokenBytes = New-Object byte[] 32
    $rng.GetBytes($tokenBytes)
    $AdminToken = ([BitConverter]::ToString($tokenBytes)).Replace("-", "").ToLowerInvariant()
} finally {
    $rng.Dispose()
}
$PriorAdminToken = $env:AEGIS_ADMIN_TOKEN
$env:AEGIS_ADMIN_TOKEN = $AdminToken
$env:PYTHONUTF8 = "1"
$steps = @()
$beforeTemp = @(
    Get-ChildItem -LiteralPath $env:TEMP -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(skill-upload|mcp-upload|dependency-upload)-' } |
        Select-Object -ExpandProperty FullName
)

try {
    $step = Invoke-LoggedStep "01-bootstrap-runtimes" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $ProjectRoot "bootstrap_runtimes.ps1"), "-Component", "All"
    )
    $steps += $step.metadata
    $Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        throw "Bootstrap did not create the locked MCP/backend Python runtime."
    }

    $verificationPath = Join-Path $EvidenceRoot "vm_attestation_verification.json"
    $step = Invoke-LoggedStep "02-verify-vm-attestation" $Python @(
        (Join-Path $DemoRoot "tools\release\verify_vm_attestation.py"),
        "--attestation", $AttestationPath,
        "--project-root", $ProjectRoot,
        "--expected-commit", $ExpectedCommit,
        "--expected-ref", $ExpectedRef,
        "--repository-url", $RepositoryUrl,
        "--output", $verificationPath
    )
    $steps += $step.metadata

    $frontend = Join-Path $DemoRoot "frontend"
    $step = Invoke-LoggedStep "03-frontend-frozen-install" $Pnpm @("install", "--frozen-lockfile") $frontend
    $steps += $step.metadata
    $step = Invoke-LoggedStep "04-backend-tests" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $DemoRoot "run_tests.ps1")
    )
    $steps += $step.metadata
    $step = Invoke-LoggedStep "05-frontend-tests" $Pnpm @("test") $frontend
    $steps += $step.metadata
    $step = Invoke-LoggedStep "06-frontend-build" $Pnpm @("run", "build") $frontend
    $steps += $step.metadata

    $preflightStep = Invoke-LoggedStep "07-preflight" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $DemoRoot "preflight.ps1"), "-Json"
    )
    $steps += $preflightStep.metadata
    try { $preflight = $preflightStep.output | ConvertFrom-Json } catch { throw "Post-bootstrap preflight did not return JSON." }
    if ($preflight.ready -ne $true -or [int]$preflight.required_failures -ne 0) {
        throw "Post-bootstrap preflight did not pass its required checks."
    }
    Write-Utf8Json (Join-Path $EvidenceRoot "preflight.json") $preflight

    foreach ($proxyName in @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "AEGIS_PIP_AUDIT_CACHE_DIR")) {
        $PriorEnvironment[$proxyName] = [Environment]::GetEnvironmentVariable($proxyName, "Process")
    }
    $env:HTTP_PROXY = "http://127.0.0.1:9"
    $env:HTTPS_PROXY = "http://127.0.0.1:9"
    $env:ALL_PROXY = "http://127.0.0.1:9"
    $env:NO_PROXY = "127.0.0.1,localhost,::1"
    $env:AEGIS_PIP_AUDIT_CACHE_DIR = Join-Path $EvidenceRoot "offline-pip-audit-cache"
    $offlineStart = Invoke-LoggedStep "08-offline-server-start" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $DemoRoot "start_demo.ps1"), "-NoBrowser", "-Port", [string]($Port + 1)
    )
    $steps += $offlineStart.metadata
    $OfflineServerStarted = $true
    $offlineOutput = Join-Path $EvidenceRoot "offline_dependency"
    $offlineProbe = Invoke-LoggedStep "09-offline-dependency-probe" $Python @(
        (Join-Path $DemoRoot "tools\release\run_release_http_acceptance.py"),
        "--mode", "dependency-offline",
        "--base-url", ("http://127.0.0.1:" + ($Port + 1)),
        "--output", $offlineOutput
    )
    $steps += $offlineProbe.metadata
    Stop-AegisServer
    $OfflineServerStarted = $false
    Copy-ServerLogs "offline"
    foreach ($proxyName in $PriorEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($proxyName, $PriorEnvironment[$proxyName], "Process")
    }

    $supplyOutput = Join-Path $EvidenceRoot "project_supply_chain"
    $step = Invoke-LoggedStep "10-project-supply-chain" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $DemoRoot "audit_project_supply_chain.ps1"),
        "-OutputDirectory", $supplyOutput
    )
    $steps += $step.metadata

    $start = Invoke-LoggedStep "11-server-start" powershell.exe @(
        "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
        (Join-Path $DemoRoot "start_demo.ps1"), "-NoBrowser", "-Port", [string]$Port
    )
    $steps += $start.metadata
    $ServerStarted = $true
    $httpOutput = Join-Path $EvidenceRoot "http_acceptance"
    $http = Invoke-LoggedStep "12-http-four-chain-e2e" $Python @(
        (Join-Path $DemoRoot "tools\release\run_release_http_acceptance.py"),
        "--mode", "full",
        "--base-url", ("http://127.0.0.1:" + $Port),
        "--output", $httpOutput
    )
    $steps += $http.metadata
    Stop-AegisServer
    $ServerStarted = $false
    Copy-ServerLogs "release"

    $afterTemp = @(
        Get-ChildItem -LiteralPath $env:TEMP -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(skill-upload|mcp-upload|dependency-upload)-' } |
            Select-Object -ExpandProperty FullName
    )
    $newTempResiduals = @($afterTemp | Where-Object { $beforeTemp -notcontains $_ })
    $jobRoot = Join-Path $DemoRoot "data\dynamic-audit-jobs"
    $jobResiduals = if (Test-Path -LiteralPath $jobRoot) { @(Get-ChildItem -LiteralPath $jobRoot -Force -ErrorAction SilentlyContinue).Count } else { 0 }
    $dockerResiduals = 0
    $dockerProbe = "unavailable"
    . (Join-Path $DemoRoot "scripts\portable_runtime.ps1")
    try { $docker = Resolve-AegisDockerCli } catch { $docker = $null }
    if ($docker) {
        $dockerText = (& $docker --context desktop-linux ps -a --filter "name=aegis-dyn-" --format "{{.ID}}" 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) {
            $dockerProbe = "completed"
            $dockerResiduals = @($dockerText -split "`r?`n" | Where-Object { $_ }).Count
        } else {
            $dockerProbe = "engine-unavailable"
        }
    }
    $trackedStatus = (& $Git -C $ProjectRoot status --porcelain=v1 --untracked-files=no 2>&1 | Out-String).Trim()
    if ($newTempResiduals.Count -ne 0 -or $jobResiduals -ne 0 -or $dockerResiduals -ne 0 -or $trackedStatus) {
        throw "Release cleanup failed: temp=$($newTempResiduals.Count), jobs=$jobResiduals, containers=$dockerResiduals, tracked_dirty=$([bool]$trackedStatus)."
    }

    $httpResult = Get-Content -LiteralPath (Join-Path $httpOutput "http_acceptance.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $offlineResult = Get-Content -LiteralPath (Join-Path $offlineOutput "offline_dependency_probe.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $supplyResult = Get-Content -LiteralPath (Join-Path $supplyOutput "project_supply_chain_report.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $supplyGates = @($supplyResult.gates.PSObject.Properties)
    $supplyGatesPassed = @($supplyGates | Where-Object { $_.Value -eq $true }).Count
    $exportedArtifacts = 0
    foreach ($chain in @($httpResult.static_chains.PSObject.Properties)) {
        $exportedArtifacts += @($chain.Value.exports).Count
    }
    $dynamicChainsCompleted = [int]($httpResult.dynamic_chain.status -eq "completed")
    $Stopwatch.Stop()
    $metrics = [ordered]@{
        schema_version = "1.0"
        status = "completed"
        vm_proof_accepted = 1
        fresh_remote_clone_verified = 1
        prebootstrap_negative_control_passed = 1
        locked_tool_downloads_verified = @($attestation.toolchain.downloads).Count
        postbootstrap_required_failures = [int]$preflight.required_failures
        backend_test_step_passed = 1
        frontend_test_step_passed = 1
        frontend_build_step_passed = 1
        project_supply_chain_gates_passed = $supplyGatesPassed
        project_supply_chain_gates_total = $supplyGates.Count
        static_chains_completed = @($httpResult.static_chains.PSObject.Properties).Count
        dynamic_chains_completed = $dynamicChainsCompleted
        exported_artifacts = $exportedArtifacts
        offline_dependency_fail_closed = [int][bool]$offlineResult.fail_closed_verified
        missing_admin_token_rejected = [int]($httpResult.authentication.missing_token_status -eq 401)
        upload_temp_residuals = $newTempResiduals.Count
        dynamic_job_residuals = $jobResiduals
        docker_container_residuals = $dockerResiduals
        tracked_file_changes = [int][bool]$trackedStatus
        administrator_token_leaks = 0
        elapsed_seconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 3)
    }
    if (
        $metrics.project_supply_chain_gates_passed -ne $metrics.project_supply_chain_gates_total -or
        $metrics.static_chains_completed -ne 3 -or
        $metrics.dynamic_chains_completed -ne 1 -or
        $metrics.exported_artifacts -ne 7 -or
        $metrics.missing_admin_token_rejected -ne 1 -or
        $metrics.offline_dependency_fail_closed -ne 1
    ) {
        throw "Release metrics did not satisfy the registered gates."
    }
    Write-Utf8Json (Join-Path $EvidenceRoot "metrics.json") $metrics

    $sourcePaths = @(
        "demo_web/release_vm/Initialize-AegisAcceptanceGuest.ps1",
        "demo_web/release_vm/Invoke-AegisReleaseAcceptance.ps1",
        "demo_web/release_vm/toolchain.windows-x64.json",
        "demo_web/tools/release/run_release_http_acceptance.py",
        "demo_web/tools/release/verify_vm_attestation.py"
    )
    $sources = [ordered]@{}
    foreach ($relative in $sourcePaths) {
        $path = Join-Path $ProjectRoot ($relative -replace '/', '\')
        $sources[$relative] = [ordered]@{
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $path).Length
        }
    }
    $runManifest = [ordered]@{
        schema_version = "1.0"
        run_id = $RunId
        status = "completed"
        experiment_tier = "release-gate/real-vm"
        branch = ($ExpectedRef -replace '^refs/heads/', '')
        commit = $ExpectedCommit
        research_question = "Can a real clean Windows VM reproduce Aegis Chain from a private remote clone and complete the four-chain release workflow without retained workspaces or fail-open degradation?"
        null_hypothesis = "At least one of VM proof, remote provenance, clean bootstrap, static chains, controlled dynamic chain, exports, degradation behavior, or cleanup fails."
        alternative_hypothesis = "All registered clean-VM release gates pass with fail-closed degradation and zero residual workspaces."
        started_at = $StartedAt.ToString("o")
        completed_at = [DateTimeOffset]::UtcNow.ToString("o")
        elapsed_seconds = $metrics.elapsed_seconds
        environment = [ordered]@{
            virtual_machine = $attestation.virtual_machine
            gpu_used = $false
            cloud_used = $false
            third_party_samples_executed = 0
        }
        repository = [ordered]@{
            url = $RepositoryUrl
            ref = $ExpectedRef
            commit = $ExpectedCommit
            fresh_clone = $true
        }
        registered_gates = [ordered]@{
            real_vm_only = $true
            fresh_remote_clone = $true
            tool_download_sha256 = $true
            prebootstrap_failure_control = $true
            postbootstrap_preflight = $true
            backend_and_frontend_regression = $true
            project_supply_chain = $true
            skill_mcp_dependency_dynamic_http_e2e = $true
            query_and_export = $true
            dependency_provider_offline_fail_closed = $true
            docker_absence_or_readiness_explicit = $true
            stop_and_residual_cleanup = $true
            tracked_checkout_unchanged = $true
        }
        steps = $steps
        metrics = $metrics
        sources = $sources
        limitations = @(
            "The release gate proves one disposable Windows VM configuration, not every Windows edition or enterprise endpoint control product.",
            "Dynamic execution remains limited to self-built hash-locked fixtures and does not execute uploaded third-party Skills or MCP servers.",
            "Docker Skill closure is executed only when its locked local image is available; otherwise the API must return an explicit 503 degradation."
        )
    }
    Write-Utf8Json (Join-Path $EvidenceRoot "run_manifest.json") $runManifest

    $summary = @"
# P0-5 真实 Windows VM 发布验收摘要

- run id：`$RunId`
- 状态：通过
- VM 提供方：`$($attestation.virtual_machine.provider)`
- 远端提交：`$ExpectedCommit`
- 全新克隆：已证明；引导前 Skill/MCP 运行时均不存在且 preflight 按预期失败。
- 引导后：必需 preflight 失败 0；后端、前端测试与构建通过；项目自身供应链门全部通过。
- HTTP 四链：Skill、MCP、依赖、内置受控动态 fixture 均完成；任务查询和 7 份导出成功。
- 降级：漏洞库网络故障形成 failed/UNKNOWN 且失败闭锁；Docker 不可用时返回明确 503，可用时执行固定镜像闭包。
- 清理：新增上传临时目录 0、动态任务工作区残留 0、Docker 容器残留 0、跟踪文件变更 0。
- 边界：本验收不执行第三方代码，不证明强沙箱或生产多租户能力。
"@
    Write-Utf8Text (Join-Path $EvidenceRoot "summary.md") ($summary.Trim() + "`n")
    $claim = @"
# Claim validation

Decision: **supported_on_one_real_clean_windows_vm**

The run supports a release-candidate claim for reproducible installation and the registered four-chain workflow on the attested VM. It does not change the static-rule decision, the sealed regression result, or the production NO-GO decision. P1/P2 controls remain required before any production claim.
"@
    Write-Utf8Text (Join-Path $EvidenceRoot "claim_validation.md") ($claim.Trim() + "`n")

    $tokenLeaks = 0
    foreach ($file in Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse) {
        try {
            $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
            if ($text.Contains($AdminToken)) { $tokenLeaks++ }
        } catch { }
    }
    if ($tokenLeaks -ne 0) {
        throw "Administrator token appeared in $tokenLeaks evidence file(s)."
    }

    $artifacts = @()
    foreach ($file in Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse | Sort-Object FullName) {
        if ($file.Name -eq "artifact_manifest.json") { continue }
        $artifacts += [ordered]@{
            path = $file.FullName.Substring($EvidenceRoot.Length).TrimStart('\').Replace('\', '/')
            bytes = $file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    Write-Utf8Json (Join-Path $EvidenceRoot "artifact_manifest.json") ([ordered]@{
        schema_version = "1.0"
        run_id = $RunId
        artifacts = $artifacts
    })
    Write-Host "PASS P0-5 clean Windows VM release gate. Evidence: $EvidenceRoot"
    exit 0
} catch {
    $Stopwatch.Stop()
    $failure = [ordered]@{
        schema_version = "1.0"
        run_id = $RunId
        status = "failed"
        failed_at = [DateTimeOffset]::UtcNow.ToString("o")
        elapsed_seconds = [math]::Round($Stopwatch.Elapsed.TotalSeconds, 3)
        error_type = $_.Exception.GetType().Name
        error = $_.Exception.Message
        expected_commit = $ExpectedCommit
        evidence_is_release_acceptance = $false
    }
    Write-Utf8Json (Join-Path $EvidenceRoot "failure.json") $failure
    Write-Error $_.Exception.Message
    exit 1
} finally {
    if ($ServerStarted -or $OfflineServerStarted) {
        try { Stop-AegisServer } catch { }
    }
    foreach ($proxyName in $PriorEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($proxyName, $PriorEnvironment[$proxyName], "Process")
    }
    $env:AEGIS_ADMIN_TOKEN = $PriorAdminToken
    $AdminToken = $null
}
