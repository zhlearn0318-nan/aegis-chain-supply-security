[CmdletBinding()]
param(
    [ValidateRange(0, 10)][int]$PauseSeconds = 2,
    [switch]$KeepInstalled,
    [string]$ReportDirectory = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
$DatasetRoot = Join-Path $ProjectRoot "datasets\skilltrustbench_v1_0"
$ManifestPath = Join-Path $DatasetRoot "full\full_manifest.jsonl"
$SafeSource = Join-Path $DatasetRoot "full\cases\case_00906"
$MaliciousSource = Join-Path $DatasetRoot "full\cases\case_01084"
$AuditTool = Join-Path $DemoRoot "tools\openclaw_install_policy_audit.py"
$Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
$Node = Join-Path $env:ProgramFiles "nodejs\node.exe"
$OpenClaw = Join-Path $env:APPDATA "npm\node_modules\openclaw\openclaw.mjs"
$OpenClawConfig = Join-Path $env:USERPROFILE ".openclaw\openclaw.json"

$RunStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunSuffix = [Guid]::NewGuid().ToString("N").Substring(0, 6)
$RunId = "openclaw-live-$RunStamp-$RunSuffix"
$SafeSlug = "aegis-live-safe-$RunStamp-$RunSuffix"
$MaliciousSlug = "aegis-live-malicious-$RunStamp-$RunSuffix"

if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path $DemoRoot "data\live-demo-reports"
}
$ReportPath = Join-Path $ReportDirectory "$RunId.json"

$ExpectedHashes = [ordered]@{
    manifest = "3a061cda6145151fbac0cbabfab7ee16e7ca60d50659eb45c73807dd037ba6ac"
    safe_skill = "f928ae5efe62d5574b518b311aee5c217ddb09c69c897d144887a55f7bdd171f"
    safe_python = "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced"
    malicious_skill = "919ec70a6f2e0a43402454ac16ca534175aa93658bf719ce524adebb39ffbfe2"
    malicious_python = "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced"
    malicious_marker = "14e8408055d816ab3af79ff2f7356b91d7a8c43b3dda6ac17cd450d41f079bc2"
}

$Result = [ordered]@{
    schema_version = "1.0"
    run_id = $RunId
    started_at = (Get-Date).ToUniversalTime().ToString("o")
    accepted = $false
    preflight = [ordered]@{}
    sample_comparison = [ordered]@{}
    safe = [ordered]@{}
    malicious = [ordered]@{}
    audit = [ordered]@{}
    cleanup = [ordered]@{}
    limits = @(
        "本次动态结论只适用于固定样本、固定输入和固定容器策略。",
        "Python 审计钩子不是不可绕过的内核级遥测。",
        "Docker Desktop/WSL2 不等价于恶意代码专用虚拟机。"
    )
}

$SafeDestination = $null
$MaliciousDestination = $null
$SafeCreated = $false
$MaliciousCreated = $false
$FatalMessage = ""

function Write-Banner {
    try { Clear-Host } catch { }
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host " Aegis Chain × OpenClaw：第三方 Skill 安装前安全准入演示" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "演示目标：正常 Skill 放行，恶意变体阻断，全程留痕且无容器残留。"
    Write-Host "运行编号：$RunId"
    Write-Host ""
}

function Write-Step {
    param([int]$Number, [string]$Title, [string]$Explanation)
    Write-Host ""
    Write-Host "[$Number] $Title" -ForegroundColor Yellow
    Write-Host $Explanation -ForegroundColor DarkGray
    if ($PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }
}

function Write-Pass {
    param([string]$Message)
    Write-Host "  [PASS] $Message" -ForegroundColor Green
}

function Invoke-CapturedCommand {
    param([string]$FilePath, [string[]]$ArgumentList)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $text = & $FilePath @ArgumentList 2>&1 | Out-String
        $code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    } catch {
        $text = $_.Exception.Message
        $code = 1
    }
    $watch.Stop()
    [pscustomobject]@{
        exit_code = $code
        duration_ms = $watch.ElapsedMilliseconds
        output = $text.Trim()
    }
}

function Assert-File {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 不存在：$Path"
    }
}

function Assert-Directory {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Label 不存在：$Path"
    }
}

function Get-Sha256 {
    param([string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Hash {
    param([string]$Path, [string]$Expected, [string]$Label)
    $actual = Get-Sha256 $Path
    if ($actual -ne $Expected) {
        throw "$Label 哈希不匹配，已拒绝继续演示。"
    }
    $actual
}

function Get-RelativeFileMap {
    param([string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root)
    $map = @{}
    foreach ($file in Get-ChildItem -LiteralPath $rootFull -Recurse -File) {
        $fileFull = [IO.Path]::GetFullPath($file.FullName)
        if (-not $fileFull.StartsWith($rootFull.TrimEnd("\") + "\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "文件路径逃逸来源目录：$fileFull"
        }
        $relative = $fileFull.Substring($rootFull.TrimEnd("\").Length).TrimStart("\").Replace("\", "/")
        $map[$relative] = $file.FullName
    }
    $map
}

function Test-InstalledPayload {
    param([string]$Source, [string]$Destination, [string]$ExpectedSlug)
    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
        return [pscustomobject]@{ valid = $false; reason = "destination_missing" }
    }
    $sourceFiles = Get-RelativeFileMap $Source
    $installedFiles = Get-RelativeFileMap $Destination
    $expectedNames = @($sourceFiles.Keys) + ".openclaw/source-origin.json"
    $nameDelta = Compare-Object -ReferenceObject @($expectedNames | Sort-Object) -DifferenceObject @($installedFiles.Keys | Sort-Object)
    if ($nameDelta) {
        return [pscustomobject]@{ valid = $false; reason = "installed_file_set_changed" }
    }
    foreach ($relative in $sourceFiles.Keys) {
        if ((Get-Sha256 $sourceFiles[$relative]) -ne (Get-Sha256 $installedFiles[$relative])) {
            return [pscustomobject]@{ valid = $false; reason = "payload_hash_mismatch"; file = $relative }
        }
    }
    try {
        $origin = Get-Content -LiteralPath $installedFiles[".openclaw/source-origin.json"] -Raw | ConvertFrom-Json
        $originValid = (
            $origin.version -eq 1 -and
            $origin.source -eq "path" -and
            $origin.slug -eq $ExpectedSlug -and
            [IO.Path]::GetFullPath([string]$origin.spec) -eq [IO.Path]::GetFullPath($Source)
        )
    } catch {
        $originValid = $false
    }
    [pscustomobject]@{
        valid = $originValid
        reason = if ($originValid) { "payload_exact_with_openclaw_origin_metadata" } else { "origin_metadata_mismatch" }
        payload_files = $sourceFiles.Count
        metadata_files = 1
    }
}

function Remove-ExactDemoDirectory {
    param([string]$SkillsRoot, [string]$Target, [string]$RequiredPrefix)
    if (-not (Test-Path -LiteralPath $Target)) { return $true }
    $rootFull = [IO.Path]::GetFullPath($SkillsRoot).TrimEnd("\")
    $targetFull = [IO.Path]::GetFullPath($Target).TrimEnd("\")
    $parentFull = [IO.Path]::GetDirectoryName($targetFull).TrimEnd("\")
    $leaf = [IO.Path]::GetFileName($targetFull)
    if ($parentFull -ne $rootFull -or -not $leaf.StartsWith($RequiredPrefix, [StringComparison]::Ordinal)) {
        throw "清理安全检查失败，拒绝删除非本次演示目录：$targetFull"
    }
    Remove-Item -LiteralPath $targetFull -Recurse -Force
    -not (Test-Path -LiteralPath $targetFull)
}

Write-Banner

try {
    Write-Step 1 "环境与准入策略自检" "确认 OpenClaw、Docker、审计运行时和 required 动态策略均可用。"
    Assert-File $Node "Node.js"
    Assert-File $OpenClaw "OpenClaw"
    Assert-File $OpenClawConfig "OpenClaw 配置"
    Assert-File $Python "Aegis 审计运行时"
    Assert-File $AuditTool "审计链验证工具"
    Assert-Directory $SafeSource "正常样本"
    Assert-Directory $MaliciousSource "恶意样本"

    $config = Get-Content -LiteralPath $OpenClawConfig -Raw | ConvertFrom-Json
    $policy = $config.security.installPolicy
    if ($policy.enabled -ne $true) { throw "OpenClaw Skill 安装准入策略未启用。" }
    if (@($policy.targets) -notcontains "skill") { throw "OpenClaw 准入目标未包含 skill。" }
    if ($policy.exec.env.AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY -ne "required") {
        throw "动态策略不是 required，拒绝进行正式演示。"
    }
    $Workspace = [IO.Path]::GetFullPath([string]$config.agents.defaults.workspace)
    $SkillsRoot = Join-Path $Workspace "skills"
    $AuditDatabase = [IO.Path]::GetFullPath([string]$policy.exec.env.AEGIS_OPENCLAW_AUDIT_DB)
    New-Item -ItemType Directory -Force -Path $SkillsRoot | Out-Null
    $SafeDestination = Join-Path $SkillsRoot $SafeSlug
    $MaliciousDestination = Join-Path $SkillsRoot $MaliciousSlug
    if ((Test-Path -LiteralPath $SafeDestination) -or (Test-Path -LiteralPath $MaliciousDestination)) {
        throw "本次随机演示目录已存在，拒绝覆盖。"
    }

    $configCheck = Invoke-CapturedCommand $Node @($OpenClaw, "config", "validate", "--json")
    if ($configCheck.exit_code -ne 0 -or -not (($configCheck.output | ConvertFrom-Json).valid)) {
        throw "OpenClaw 配置校验失败。"
    }

    $Docker = $null
    foreach ($entry in ([string]$policy.exec.env.PATH -split ";")) {
        $candidate = Join-Path $entry "docker.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $Docker = $candidate; break }
    }
    if (-not $Docker) {
        $candidate = Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $Docker = $candidate }
    }
    if (-not $Docker) { throw "未找到 Docker CLI。" }
    $dockerCheck = Invoke-CapturedCommand $Docker @("--context", "desktop-linux", "info", "--format", "{{.ServerVersion}}")
    if ($dockerCheck.exit_code -ne 0) { throw "Docker Desktop Linux Engine 不可用。" }

    $Result.preflight = [ordered]@{
        openclaw_config_valid = $true
        policy_enabled = $true
        target_skill = $true
        dynamic_policy = "required"
        docker_engine = $dockerCheck.output
        windows_acl_compatibility = [bool]$policy.exec.allowInsecurePath
    }
    Write-Pass "OpenClaw 配置有效，Skill 准入已启用，动态策略为 required。"
    Write-Pass "Docker Desktop Linux Engine 可用（$($dockerCheck.output)）。"

    Write-Step 2 "权威样本身份与完整性核验" "使用固定版本 SkillTrustBench；正常与恶意样本功能同名、主程序完全相同。"
    Assert-Hash $ManifestPath $ExpectedHashes.manifest "SkillTrustBench 完整清单" | Out-Null
    $safeSkillHash = Assert-Hash (Join-Path $SafeSource "SKILL.md") $ExpectedHashes.safe_skill "正常样本 SKILL.md"
    $safePythonHash = Assert-Hash (Join-Path $SafeSource "meeting_notes_generator.py") $ExpectedHashes.safe_python "正常样本主程序"
    $badSkillHash = Assert-Hash (Join-Path $MaliciousSource "SKILL.md") $ExpectedHashes.malicious_skill "恶意样本 SKILL.md"
    $badPythonHash = Assert-Hash (Join-Path $MaliciousSource "meeting_notes_generator.py") $ExpectedHashes.malicious_python "恶意样本主程序"
    $markerHash = Assert-Hash (Join-Path $MaliciousSource "scripts\_tool_override_marker.py") $ExpectedHashes.malicious_marker "恶意隐藏脚本"
    if ($safePythonHash -ne $badPythonHash) { throw "配对样本主程序不再相同。" }
    $Result.sample_comparison = [ordered]@{
        dataset_revision = "762d5388b3a047b26df9679582af868a0e5b2c8f"
        safe_case = "case_00906"
        malicious_case = "case_01084"
        same_main_python_sha256 = $safePythonHash
        skill_manifest_changed = ($safeSkillHash -ne $badSkillHash)
        malicious_extra_file_sha256 = $markerHash
        malicious_risk_labels = @("T01", "T04", "T07")
    }
    Write-Pass "数据集清单与 5 个样本文件哈希全部匹配。"
    Write-Host "  相同主程序 SHA-256：$safePythonHash"
    Write-Host "  恶意变体差异：修改 SKILL.md，并新增 scripts/_tool_override_marker.py" -ForegroundColor Magenta

    Write-Step 3 "正常 Skill：静态审计后进入容器试运行" "只有静态结果可接受，才允许在无网络、只读根文件系统、非 root 容器中执行。"
    $safeInstall = Invoke-CapturedCommand $Node @($OpenClaw, "skills", "install", $SafeSource, "--as", $SafeSlug)
    $SafeCreated = Test-Path -LiteralPath $SafeDestination -PathType Container
    if ($safeInstall.exit_code -ne 0 -or -not $SafeCreated) {
        throw "正常 Skill 未能通过真实 OpenClaw 准入：$($safeInstall.output)"
    }
    $payload = Test-InstalledPayload $SafeSource $SafeDestination $SafeSlug
    if (-not $payload.valid) { throw "正常 Skill 安装文件完整性校验失败：$($payload.reason)" }
    Write-Pass "正常 Skill 安装成功，来源文件逐文件哈希一致。"

    $skillsList = Invoke-CapturedCommand $Node @($OpenClaw, "skills", "list", "--json")
    $visibleSkill = $null
    if ($skillsList.exit_code -eq 0) {
        $visibleSkill = @((($skillsList.output | ConvertFrom-Json).skills) | Where-Object name -eq "meeting-notes-generator" | Select-Object -First 1)
    }
    $skillVisible = ($visibleSkill.Count -eq 1 -and $visibleSkill[0].eligible -eq $true -and $visibleSkill[0].modelVisible -eq $true)
    if (-not $skillVisible) { throw "OpenClaw 未将正常 Skill 识别为模型可见能力。" }
    Write-Pass "OpenClaw 已识别 meeting-notes-generator：eligible=true，modelVisible=true。"

    Write-Step 4 "恶意同名变体：安装提交前阻断" "恶意包的主程序未变化，但完整包中夹带了隐藏工具覆盖文件。"
    $badInstall = Invoke-CapturedCommand $Node @($OpenClaw, "skills", "install", $MaliciousSource, "--as", $MaliciousSlug)
    $MaliciousCreated = Test-Path -LiteralPath $MaliciousDestination -PathType Container
    if ($badInstall.exit_code -eq 0 -or $MaliciousCreated) {
        throw "恶意 Skill 未被可靠阻断。"
    }
    Write-Pass "恶意 Skill 被安装策略拒绝，目标目录未生成。"

    Write-Step 5 "审计证据与失败关闭核验" "验证正常样本有动态清洁证明，恶意样本只有静态阻断证据且从未执行。"
    $auditResult = Invoke-CapturedCommand $Python @($AuditTool, "--database", $AuditDatabase, "--limit", "30")
    if ($auditResult.exit_code -ne 0) { throw "审计哈希链验证失败。" }
    $auditPayload = $auditResult.output | ConvertFrom-Json
    $safeAudit = @($auditPayload.events | Where-Object target_name -eq $SafeSlug | Select-Object -First 1)
    $badAudit = @($auditPayload.events | Where-Object target_name -eq $MaliciousSlug | Select-Object -First 1)
    if ($safeAudit.Count -ne 1 -or $badAudit.Count -ne 1) { throw "缺少本次演示的审计事件。" }
    $safeRules = @($safeAudit[0].finding_rule_ids)
    $badRules = @($badAudit[0].finding_rule_ids)
    $safeDynamicClean = $safeRules -contains "AEGIS_DYNAMIC_EXECUTION_CLEAN"
    $badDynamicExecuted = @($badRules | Where-Object { ([string]$_).StartsWith("AEGIS_DYNAMIC_", [StringComparison]::Ordinal) }).Count -gt 0
    if ($safeAudit[0].decision -ne "allow" -or -not $safeDynamicClean) { throw "正常样本缺少动态清洁证明。" }
    if ($badAudit[0].decision -ne "block" -or $badDynamicExecuted) { throw "恶意样本的失败关闭证据不符合预期。" }
    Write-Pass "审计哈希链有效，共 $($auditPayload.verification.rows) 条记录。"
    Write-Host "  正常样本：ALLOW；规则 = $($safeRules -join ', ')" -ForegroundColor Green
    Write-Host "  恶意样本：BLOCK；规则 = $($badRules -join ', ')" -ForegroundColor Red
    Write-Pass "恶意样本动态执行次数为 0。"

    Write-Step 6 "容器清理与零残留核验" "动态容器必须在取证后删除；阻断样本不得生成安装目录。"
    $containerQuery = Invoke-CapturedCommand $Docker @(
        "--context", "desktop-linux", "container", "ls", "--all",
        "--filter", "label=aegis.dynamic.backend=aegis-python-skill-sandbox-v1",
        "--format", "{{.ID}}"
    )
    if ($containerQuery.exit_code -ne 0) { throw "无法核验动态容器残留。" }
    $containerResiduals = @($containerQuery.output -split "`r?`n" | Where-Object { $_.Trim() }).Count
    if ($containerResiduals -ne 0) { throw "发现 $containerResiduals 个 Aegis 动态容器残留。" }
    Write-Pass "Docker 动态容器残留为 0，恶意安装目录残留为 0。"

    $Result.safe = [ordered]@{
        slug = $SafeSlug
        installed = $true
        install_exit_code = $safeInstall.exit_code
        end_to_end_duration_ms = $safeInstall.duration_ms
        payload_valid = [bool]$payload.valid
        openclaw_eligible = $true
        openclaw_model_visible = $true
        audit_decision = $safeAudit[0].decision
        audit_duration_ms = $safeAudit[0].duration_ms
        finding_rule_ids = $safeRules
    }
    $Result.malicious = [ordered]@{
        slug = $MaliciousSlug
        installed = $false
        install_exit_code = $badInstall.exit_code
        end_to_end_duration_ms = $badInstall.duration_ms
        audit_decision = $badAudit[0].decision
        audit_duration_ms = $badAudit[0].duration_ms
        finding_rule_ids = $badRules
        dynamic_executed = $false
    }
    $Result.audit = [ordered]@{
        chain_valid = [bool]$auditPayload.verification.valid
        rows = $auditPayload.verification.rows
        head_chain_sha256 = $auditPayload.verification.head_chain_sha256
        docker_container_residuals = $containerResiduals
        gpu_used = $false
    }
    $Result.accepted = $true
} catch {
    $FatalMessage = $_.Exception.Message
    $Result.accepted = $false
    $Result.error = $FatalMessage
} finally {
    Write-Step 7 "清理本次演示对象并保留报告" "只删除带本次随机编号的演示目录；既有 Skill、配置和审计记录均不修改。"
    try {
        if ($KeepInstalled) {
            $Result.cleanup.safe_removed = $false
            $Result.cleanup.reason = "KeepInstalled requested"
        } elseif ($null -ne $SafeDestination -and ($SafeCreated -or (Test-Path -LiteralPath $SafeDestination))) {
            $Result.cleanup.safe_removed = Remove-ExactDemoDirectory $SkillsRoot $SafeDestination "aegis-live-safe-"
        } else {
            $Result.cleanup.safe_removed = $true
        }
        if ($null -ne $MaliciousDestination -and ($MaliciousCreated -or (Test-Path -LiteralPath $MaliciousDestination))) {
            $Result.cleanup.malicious_removed = Remove-ExactDemoDirectory $SkillsRoot $MaliciousDestination "aegis-live-malicious-"
        } else {
            $Result.cleanup.malicious_removed = $true
        }
        if (-not $KeepInstalled) {
            Write-Pass "本次临时 Skill 已清理；审计记录和机器报告已保留。"
        }
    } catch {
        $Result.cleanup.error = $_.Exception.Message
        $Result.accepted = $false
        if (-not $FatalMessage) { $FatalMessage = $_.Exception.Message }
        Write-Host "  [FAIL] 清理失败：$($_.Exception.Message)" -ForegroundColor Red
    }
    $Result.finished_at = (Get-Date).ToUniversalTime().ToString("o")
    New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null
    $Result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportPath -Encoding utf8
}

Write-Host ""
Write-Host "======================= 演示结论 =======================" -ForegroundColor Cyan
if ($Result.accepted) {
    Write-Host "[ACCEPTED] OpenClaw 第三方 Skill 安装前安全准入闭环通过" -ForegroundColor Green
    Write-Host "  正常样本：ALLOW + 动态清洁证明 + 安装成功"
    Write-Host "  恶意样本：BLOCK + 未执行 + 无安装残留"
    Write-Host "  审计链：有效；Docker 残留：0；GPU：未使用"
} else {
    Write-Host "[FAILED] 本次演示没有达到接受标准" -ForegroundColor Red
    Write-Host "  原因：$FatalMessage" -ForegroundColor Red
}
Write-Host "  报告：$ReportPath"
Write-Host "========================================================" -ForegroundColor Cyan

if ($Result.accepted) { exit 0 }
exit 1
