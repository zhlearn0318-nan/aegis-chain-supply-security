@echo off
setlocal
chcp 65001 >nul
title Aegis Chain + OpenClaw Final Installer
cd /d "%~dp0"

echo Aegis Chain + OpenClaw Windows final installer
echo This window will stay open so you can read the result.
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_openclaw_final.ps1"
set "AEGIS_EXIT=%ERRORLEVEL%"

echo.
if "%AEGIS_EXIT%"=="0" (
  echo [SUCCESS] Installation and verification completed.
) else (
  echo [FAILED] Installation stopped safely. Read the error and log above.
)
echo.
pause
exit /b %AEGIS_EXIT%
