[CmdletBinding()]
param([switch]$RunTests)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
. (Join-Path $Root "demo_web\scripts\portable_runtime.ps1")
$SkillPython = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $Root ".runtime_skill")
$SkillScanner = Join-Path $Root ".runtime_skill\Scripts\skill-scanner.exe"
$McpPython = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $Root ".runtime_mcp313")
$McpScripts = Join-Path $Root ".runtime_mcp313\Scripts"
$McpScanner = Join-Path $McpScripts "mcp-scanner.exe"
$PipAudit = Join-Path $McpScripts "pip-audit.exe"
Add-AegisRuntimeToPath -RuntimeRoots @(
    (Join-Path $Root ".runtime_skill"),
    (Join-Path $Root ".runtime_mcp313")
) | Out-Null

foreach ($required in @($SkillPython, $SkillScanner, $McpPython, $McpScanner, $PipAudit)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing runtime component: $required. See QUICKSTART.md."
    }
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

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

$VulnerableOutput = Join-Path $Root "results\mcp_vulnerable_urllib3_current.json"
& $McpScanner vulnerable-package `
    (Join-Path $Root "fixtures\vulnerable_dependencies\requirements_urllib3.txt") `
    --no-deps --disable-pip --output $VulnerableOutput --format summary
if ($LASTEXITCODE -ne 0) { throw "MCP vulnerable dependency scan failed" }
$VulnerableReport = Get-Content -Raw -LiteralPath $VulnerableOutput | ConvertFrom-Json
$VulnerableCount = @($VulnerableReport | Where-Object { -not $_.is_safe }).Count
if ($VulnerableCount -lt 1) {
    throw "Expected vulnerable urllib3 findings, observed none; refusing a false-safe result."
}

$SafeOutput = Join-Path $Root "results\mcp_vulnerable_safe_current.json"
& $McpScanner vulnerable-package `
    (Join-Path $Root "fixtures\vulnerable_dependencies\requirements_safe_latest.txt") `
    --no-deps --disable-pip --output $SafeOutput --format summary
if ($LASTEXITCODE -ne 0) { throw "MCP safe dependency scan failed" }
$SafeReport = Get-Content -Raw -LiteralPath $SafeOutput | ConvertFrom-Json
$UnsafeSafeCount = @($SafeReport | Where-Object { -not $_.is_safe }).Count
if (@($SafeReport).Count -lt 1 -or $UnsafeSafeCount -ne 0) {
    throw "Expected a non-empty safe dependency result with zero vulnerabilities."
}

if ($RunTests) {
    $SkillTemp = Join-Path $Root ("results\pytest-skill-" + [guid]::NewGuid().ToString("N"))
    $McpTemp = Join-Path $Root ("results\pytest-mcp-" + [guid]::NewGuid().ToString("N"))

    Push-Location (Join-Path $Root "third_party\skill-scanner")
    try {
        & $SkillPython -m pytest tests\test_scanner.py tests\test_yara_true_positives.py tests\behavioral `
            -q -o addopts= -p no:cacheprovider --basetemp $SkillTemp
        if ($LASTEXITCODE -ne 0) { throw "Skill Scanner targeted tests failed" }
    } finally {
        Pop-Location
    }

    Push-Location (Join-Path $Root "third_party\mcp-scanner")
    try {
        & $McpPython -m pytest tests\test_yara_analyzer.py tests\test_yara_rules_coverage.py tests\test_vulnerable_package_analyzer.py `
            -q -o addopts= -p no:cacheprovider --basetemp $McpTemp
        if ($LASTEXITCODE -ne 0) { throw "MCP Scanner targeted tests failed" }
    } finally {
        Pop-Location
    }
}

Write-Host "Cisco scanner reproduction completed and fail-closed checks passed."
