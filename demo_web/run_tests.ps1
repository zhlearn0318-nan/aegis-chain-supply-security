$ErrorActionPreference = "Stop"
$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
. (Join-Path $DemoRoot "scripts\portable_runtime.ps1")
$Python = Resolve-AegisRuntimePython -RuntimeRoot (Join-Path $ProjectRoot ".runtime_mcp313")
$TestTemp = Join-Path $DemoRoot "data\test-temp"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "缺少测试运行环境：$Python"
}

New-Item -ItemType Directory -Force -Path $TestTemp | Out-Null
$env:TEMP = $TestTemp
$env:TMP = $TestTemp

Push-Location $DemoRoot
try {
    & $Python -m pytest backend\tests -q
    if ($LASTEXITCODE -ne 0) { throw "自动测试失败，退出码：$LASTEXITCODE" }
} finally {
    Pop-Location
}
