[CmdletBinding()]
param(
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$SkillPython = Join-Path $Root ".runtime_skill\Scripts\python.exe"
$SkillScanner = Join-Path $Root ".runtime_skill\Scripts\skill-scanner.exe"
$McpPython = Join-Path $Root ".runtime_mcp313\Scripts\python.exe"
$McpScanner = Join-Path $Root ".runtime_mcp313\Scripts\mcp-scanner.exe"
$McpScripts = Join-Path $Root ".runtime_mcp313\Scripts"

foreach ($required in @($SkillPython, $SkillScanner, $McpPython, $McpScanner)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing runtime component: $required. See QUICKSTART.md."
    }
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:PATH = "$McpScripts;$env:PATH"

& $SkillScanner scan-all (Join-Path $Root "fixtures\skills") `
    --recursive --use-behavioral --format json `
    --output (Join-Path $Root "results\skill_scanner_current.json")
if ($LASTEXITCODE -ne 0) { throw "Skill Scanner failed with exit code $LASTEXITCODE" }

& $SkillPython (Join-Path $Root "scripts\evaluate_skill_results.py") `
    --results (Join-Path $Root "results\skill_scanner_current.json") `
    --ground-truth (Join-Path $Root "ground_truth.json") `
    --output (Join-Path $Root "results\skill_scanner_metrics_current.json")
if ($LASTEXITCODE -ne 0) { throw "Skill evaluation failed with exit code $LASTEXITCODE" }

& $McpPython (Join-Path $Root "scripts\run_mcp_static.py") `
    --scanner $McpScanner `
    --tools (Join-Path $Root "fixtures\mcp\tools.json") `
    --prompts (Join-Path $Root "fixtures\mcp\prompts.json") `
    --resources (Join-Path $Root "fixtures\mcp\resources.json") `
    --output (Join-Path $Root "results\mcp_static_current.json") `
    --expected-unsafe 3
if ($LASTEXITCODE -ne 0) { throw "MCP static scan failed with exit code $LASTEXITCODE" }

function Invoke-VerifiedMcpDependencyScan {
    param(
        [Parameter(Mandatory = $true)][string]$Requirements,
        [Parameter(Mandatory = $true)][string]$Output,
        [Parameter(Mandatory = $true)][bool]$ExpectedSafe
    )

    $PriorErrorAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $scanText = (& $McpScanner vulnerable-package $Requirements `
            --no-deps --disable-pip `
            --vulnerability-service osv `
            --output $Output `
            --format summary 2>&1 | Out-String).Trim()
        $scanExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PriorErrorAction
    }
    if ($scanText) { Write-Host $scanText }
    if ($scanExit -ne 0) { throw "MCP dependency scan failed with exit code $scanExit" }
    if ($scanText -match "pip-audit exited|produced no JSON|pip-audit error") {
        throw "MCP dependency scan reported an internal pip-audit failure and was rejected fail-closed."
    }
    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "MCP dependency scan did not create JSON output."
    }
    $parsedPayload = Get-Content -LiteralPath $Output -Raw -Encoding UTF8 | ConvertFrom-Json
    # Windows PowerShell 5 returns a top-level JSON array as one array object,
    # while PowerShell 7 enumerates it. Normalize both runtimes explicitly.
    $payload = @($parsedPayload | ForEach-Object { $_ })
    if ($payload.Count -lt 1 -or @($payload | Where-Object { $_.status -ne "completed" }).Count -gt 0) {
        throw "MCP dependency scan output is incomplete."
    }
    $findings = @($payload | ForEach-Object { $_.findings.vulnerable_package_analyzer })
    $OracleMismatches = 0
    foreach ($item in $payload) {
        if ($null -eq $item.findings.vulnerable_package_analyzer) {
            $OracleMismatches++
        } elseif ($ExpectedSafe -and -not $item.is_safe) {
            $OracleMismatches++
        } elseif (-not $ExpectedSafe -and $item.is_safe) {
            $OracleMismatches++
        }
    }
    if ($findings.Count -ne $payload.Count -or $OracleMismatches -gt 0) {
        throw "MCP dependency scan result did not match the acceptance oracle (items=$($payload.Count), findings=$($findings.Count), mismatches=$OracleMismatches, expected_safe=$ExpectedSafe)."
    }
    $TotalFindings = ($findings | Measure-Object -Property total_findings -Sum).Sum
    if ($ExpectedSafe -and [int]$TotalFindings -ne 0) {
        throw "Safe dependency fixture unexpectedly has findings."
    }
    if (-not $ExpectedSafe -and [int]$TotalFindings -le 0) {
        throw "Vulnerable dependency fixture was not detected."
    }
}

Invoke-VerifiedMcpDependencyScan `
    -Requirements (Join-Path $Root "fixtures\vulnerable_dependencies\requirements_urllib3.txt") `
    -Output (Join-Path $Root "results\mcp_vulnerable_urllib3_current.json") `
    -ExpectedSafe $false
Invoke-VerifiedMcpDependencyScan `
    -Requirements (Join-Path $Root "fixtures\vulnerable_dependencies\requirements_safe_latest.txt") `
    -Output (Join-Path $Root "results\mcp_vulnerable_safe_current.json") `
    -ExpectedSafe $true

if ($RunTests) {
    Push-Location (Join-Path $Root "third_party\skill-scanner")
    try {
        & $SkillPython -m pytest tests\test_scanner.py tests\test_yara_true_positives.py tests\behavioral -q -o addopts=
        if ($LASTEXITCODE -ne 0) { throw "Skill Scanner targeted tests failed" }
    } finally {
        Pop-Location
    }

    Push-Location (Join-Path $Root "third_party\mcp-scanner")
    try {
        & $McpPython -m pytest tests\test_yara_analyzer.py tests\test_yara_rules_coverage.py tests\test_vulnerable_package_analyzer.py -q -o addopts=
        if ($LASTEXITCODE -ne 0) { throw "MCP Scanner targeted tests failed" }
    } finally {
        Pop-Location
    }
}

Write-Host "Cisco scanner reproduction completed."
