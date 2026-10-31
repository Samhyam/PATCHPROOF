@echo off
REM PATCHPROOF launcher - double-click to start all three services.
REM Bypasses the PowerShell execution policy for this run only (no system change).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-all.ps1"
pause
