@echo off
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\Setup-Windows.ps1"
if errorlevel 1 (
  echo.
  echo Racing Speed could not complete this action. Read the error above.
)
pause
