$ErrorActionPreference = "Stop"
$PidFile = Join-Path $PSScriptRoot ".server.pid"

if (-not (Test-Path -LiteralPath $PidFile)) {
    Write-Host "没有发现正在运行的演示服务。"
    return
}

$serverPid = [int](Get-Content -LiteralPath $PidFile -Raw)
$process = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
if ($process -and $process.ProcessName -like "python*") {
    Stop-Process -Id $serverPid
    Write-Host "演示服务已停止。"
} else {
    Write-Host "PID 文件已过期，没有停止其他进程。"
}
Remove-Item -LiteralPath $PidFile -Force
