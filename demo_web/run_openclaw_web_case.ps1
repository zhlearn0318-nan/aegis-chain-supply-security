[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("safe", "malicious")][string]$Scenario,
    [Parameter(Mandatory = $true)][string]$ProjectRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $Utf8NoBom
[Console]::OutputEncoding = $Utf8NoBom
$global:OutputEncoding = $Utf8NoBom
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$DemoRoot = Join-Path $ProjectRoot "demo_web"
$DatasetRoot = Join-Path $ProjectRoot "datasets\skilltrustbench_v1_0\full\cases"
$CaseId = if ($Scenario -eq "safe") { "case_00906" } else { "case_01084" }
$Source = Join-Path $DatasetRoot $CaseId
$Slug = if ($Scenario -eq "safe") { "aegis-web-safe-demo" } else { "aegis-web-malicious-demo" }
$Node = Join-Path $env:ProgramFiles "nodejs\node.exe"
$OpenClaw = Join-Path $env:APPDATA "npm\node_modules\openclaw\openclaw.mjs"
$ConfigPath = Join-Path $env:USERPROFILE ".openclaw\openclaw.json"
$AuditTool = Join-Path $DemoRoot "tools\openclaw_install_policy_audit.py"
$Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"

function Write-RawLog {
    param([string]$Message)
    $stamp = (Get-Date).ToString("HH:mm:ss.fff")
    [Console]::Error.WriteLine("[$stamp] $Message")
}

function Invoke-Captured {
    param([string]$FilePath, [string[]]$Arguments, [switch]$EmitOutput)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $output = & $FilePath @Arguments 2>&1 | Out-String
        $code = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    } catch {
        $output = $_.Exception.Message
        $code = 1
    }
    $watch.Stop()
    if ($EmitOutput -and $output) {
        foreach ($line in ($output.Trim() -split "`r?`n")) {
            if ($line.Trim()) { Write-RawLog "[openclaw] $line" }
        }
    }
    [pscustomobject]@{ code = $code; output = $output.Trim(); duration_ms = $watch.ElapsedMilliseconds }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Remove-ExactDemoTarget([string]$SkillsRoot, [string]$Target, [string]$ExpectedLeaf) {
    if (-not (Test-Path -LiteralPath $Target)) { return }
    $rootFull = [IO.Path]::GetFullPath($SkillsRoot).TrimEnd("\")
    $targetFull = [IO.Path]::GetFullPath($Target).TrimEnd("\")
    if ([IO.Path]::GetDirectoryName($targetFull).TrimEnd("\") -ne $rootFull -or [IO.Path]::GetFileName($targetFull) -ne $ExpectedLeaf) {
        throw "Refusing to remove a non-demo directory."
    }
    Remove-Item -LiteralPath $targetFull -Recurse -Force
}

try {
    Write-RawLog "[STEP 1/6] Select fixed dataset sample: scenario=$Scenario case=$CaseId"
    foreach ($required in @($Source, $Node, $OpenClaw, $ConfigPath, $AuditTool, $Python)) {
        if (-not (Test-Path -LiteralPath $required)) { throw "Missing runtime dependency: $required" }
    }
    Write-RawLog "[preflight] Runtime dependencies are present."
    $expected = if ($Scenario -eq "safe") {
        @{ skill = "f928ae5efe62d5574b518b311aee5c217ddb09c69c897d144887a55f7bdd171f"; python = "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced" }
    } else {
        @{ skill = "919ec70a6f2e0a43402454ac16ca534175aa93658bf719ce524adebb39ffbfe2"; python = "180a7cd0be96106b0478f409192c8717ece77fe634dbaf27e2aecf29c6cdaced"; marker = "14e8408055d816ab3af79ff2f7356b91d7a8c43b3dda6ac17cd450d41f079bc2" }
    }
    if ((Get-Sha256 (Join-Path $Source "SKILL.md")) -ne $expected.skill) { throw "SKILL.md hash mismatch; scan refused." }
    if ((Get-Sha256 (Join-Path $Source "meeting_notes_generator.py")) -ne $expected.python) { throw "Main program hash mismatch; scan refused." }
    if ($Scenario -eq "malicious" -and (Get-Sha256 (Join-Path $Source "scripts\_tool_override_marker.py")) -ne $expected.marker) { throw "Malicious marker hash mismatch; scan refused." }
    Write-RawLog "[STEP 2/6] Verify sample SHA-256 and immutable identity."
    Write-RawLog "[hash] SKILL.md=$($expected.skill)"
    Write-RawLog "[hash] meeting_notes_generator.py=$($expected.python)"
    if ($Scenario -eq "malicious") { Write-RawLog "[hash] scripts/_tool_override_marker.py=$($expected.marker)" }

    $config = [IO.File]::ReadAllText($ConfigPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($config.security.installPolicy.enabled -ne $true -or @($config.security.installPolicy.targets) -notcontains "skill") { throw "OpenClaw Skill install policy is not enabled." }
    if ($config.security.installPolicy.exec.env.AEGIS_OPENCLAW_DYNAMIC_SKILL_POLICY -ne "required") { throw "Dynamic audit is not in required mode." }
    $workspace = [IO.Path]::GetFullPath([string]$config.agents.defaults.workspace)
    $skillsRoot = Join-Path $workspace "skills"
    $destination = Join-Path $skillsRoot $Slug
    $auditDb = [IO.Path]::GetFullPath([string]$config.security.installPolicy.exec.env.AEGIS_OPENCLAW_AUDIT_DB)
    New-Item -ItemType Directory -Force -Path $skillsRoot | Out-Null
    Remove-ExactDemoTarget $skillsRoot $destination $Slug
    Write-RawLog "[STEP 3/6] Validate OpenClaw security.installPolicy."
    Write-RawLog "[policy] enabled=true target=skill dynamic=required fail_closed=true"
    Write-RawLog "[workspace] target_slug=$Slug destination=$destination"

    Write-RawLog "[STEP 4/6] Execute real OpenClaw install command."
    Write-RawLog "[command] node openclaw.mjs skills install <fixed-$CaseId> --as $Slug"
    Write-RawLog "[policy] Waiting for static scan and, when allowed, Docker isolated trial."
    $install = Invoke-Captured -FilePath $Node -Arguments @($OpenClaw, "skills", "install", $Source, "--as", $Slug) -EmitOutput
    $installed = Test-Path -LiteralPath $destination -PathType Container
    Write-RawLog "[openclaw] exit_code=$($install.code) duration_ms=$($install.duration_ms) installed=$installed"
    Write-RawLog "[STEP 5/6] Verify append-only admission audit hash chain."
    $auditRun = Invoke-Captured $Python @($AuditTool, "--database", $auditDb, "--limit", "30")
    if ($auditRun.code -ne 0) { throw "Audit hash-chain verification failed: $($auditRun.output)" }
    $audit = $auditRun.output | ConvertFrom-Json
    $event = @($audit.events | Where-Object target_name -eq $Slug | Select-Object -First 1)
    if ($event.Count -ne 1) { throw "Audit event for this install was not found." }
    $rules = @($event[0].finding_rule_ids)
    $dynamicRules = @($rules | Where-Object { ([string]$_).StartsWith("AEGIS_DYNAMIC_", [StringComparison]::Ordinal) })
    Write-RawLog "[audit] event_id=$($event[0].event_id) sequence=$($event[0].sequence) chain_valid=$($audit.verification.valid)"
    Write-RawLog "[audit] decision=$($event[0].decision) reason_code=$($event[0].reason_code) duration_ms=$($event[0].duration_ms)"
    foreach ($rule in $rules) { Write-RawLog "[finding] $rule" }

    if ($Scenario -eq "safe") {
        $accepted = ($install.code -eq 0 -and $installed -and $event[0].decision -eq "allow" -and $rules -contains "AEGIS_DYNAMIC_EXECUTION_CLEAN")
        $title = "Safe Skill passed admission and was installed"
        $dynamicSummary = if ($rules -contains "AEGIS_DYNAMIC_EXECUTION_CLEAN") { "Container trial completed cleanly" } else { "Dynamic clean evidence is missing" }
    } else {
        $accepted = ($install.code -ne 0 -and -not $installed -and $event[0].decision -eq "block" -and $dynamicRules.Count -eq 0)
        $title = "Malicious Skill was blocked before install"
        $dynamicSummary = if ($dynamicRules.Count -eq 0) { "Static block; dynamic execution count is zero" } else { "Unexpected dynamic execution evidence found" }
        if ($installed) { Remove-ExactDemoTarget $skillsRoot $destination $Slug; $installed = $false }
    }
    Write-RawLog "[STEP 6/6] Finalize evidence and installation state."
    Write-RawLog "[final] accepted=$accepted decision=$(([string]$event[0].decision).ToUpperInvariant()) installed=$installed dynamic=$dynamicSummary"

    [ordered]@{
        schema_version = "1.0"
        accepted = [bool]$accepted
        scenario = $Scenario
        case_id = $CaseId
        title = $title
        decision = ([string]$event[0].decision).ToUpperInvariant()
        installed = [bool]$installed
        duration_ms = $install.duration_ms
        audit_duration_ms = $event[0].duration_ms
        audit_chain_valid = [bool]$audit.verification.valid
        finding_rule_ids = $rules
        dynamic_summary = $dynamicSummary
        target_slug = $Slug
        main_program_sha256 = $expected.python
        error = if ($accepted) { $null } else { $install.output }
    } | ConvertTo-Json -Depth 8 -Compress
    if (-not $accepted) { exit 2 }
} catch {
    Write-RawLog "[FAIL-CLOSED] $($_.Exception.Message)"
    [ordered]@{
        schema_version = "1.0"
        accepted = $false
        scenario = $Scenario
        case_id = $CaseId
        title = "Admission demo execution failed"
        decision = "ERROR"
        installed = $false
        duration_ms = 0
        audit_chain_valid = $false
        finding_rule_ids = @()
        dynamic_summary = "Failed closed"
        error = $_.Exception.Message
    } | ConvertTo-Json -Depth 6 -Compress
    exit 1
}
