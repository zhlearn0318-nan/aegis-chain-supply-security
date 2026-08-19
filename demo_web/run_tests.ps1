$ErrorActionPreference = "Stop"
$DemoRoot = $PSScriptRoot
$ProjectRoot = Split-Path $DemoRoot -Parent
$Python = Join-Path $ProjectRoot ".runtime_mcp313\Scripts\python.exe"
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
