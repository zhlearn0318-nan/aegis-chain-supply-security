@echo off
setlocal
chcp 65001 >nul

set "WINDOWS_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "AEGIS_DEMO_SCRIPT=%~dp0demo_openclaw_live_admission.ps1"
set "AEGIS_DEMO_ROOT=%~dp0"
if not defined AEGIS_DEMO_PAUSE_SECONDS set "AEGIS_DEMO_PAUSE_SECONDS=2"

if not exist "%WINDOWS_PS%" (
  echo [ERROR] Windows PowerShell was not found.
  pause
  exit /b 1
)

"%WINDOWS_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$source=[IO.File]::ReadAllText($env:AEGIS_DEMO_SCRIPT,[Text.Encoding]::UTF8); & ([ScriptBlock]::Create($source)) -PauseSeconds ([int]$env:AEGIS_DEMO_PAUSE_SECONDS) -ScriptRootOverride $env:AEGIS_DEMO_ROOT"
set "DEMO_EXIT=%ERRORLEVEL%"

echo.
if "%DEMO_EXIT%"=="0" (
  echo Demo completed. Press any key to close this window.
) else (
  echo Demo failed. Keep this window open and read the final error message.
)
if not "%AEGIS_DEMO_NO_PAUSE%"=="1" pause >nul
exit /b %DEMO_EXIT%
