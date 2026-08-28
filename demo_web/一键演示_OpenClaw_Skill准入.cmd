@echo off
setlocal
chcp 65001 >nul

set "PWSH=pwsh.exe"
where pwsh.exe >nul 2>nul
if not errorlevel 1 goto run_demo

set "PWSH=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"

if not exist "%PWSH%" (
  echo [ERROR] 未找到 PowerShell 7。请在 Codex 终端运行 demo_openclaw_live_admission.ps1。
  pause
  exit /b 1
)

:run_demo
"%PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0demo_openclaw_live_admission.ps1" -PauseSeconds 2
set "DEMO_EXIT=%ERRORLEVEL%"

echo.
if "%DEMO_EXIT%"=="0" (
  echo 演示完成。按任意键关闭窗口。
) else (
  echo 演示未通过，请保留窗口并查看最后显示的失败原因。
)
pause >nul
exit /b %DEMO_EXIT%
