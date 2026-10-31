# PATCHPROOF — start all three services (portable; paths relative to this file).
#   Person 2 backend     : http://localhost:8000
#   Person 1 scanner API : http://localhost:8100
#   Person 3 frontend    : http://localhost:5173
#
# Usage:  double-click run-all.bat  (works even when script execution is blocked), or:
#         powershell -ExecutionPolicy Bypass -File .\run-all.ps1
# Requires Python 3.11+ and Node 18+ on PATH, and the one-time installs in SETUP.md.

$root = $PSScriptRoot

# Use "python" if present, else the Windows "py" launcher.
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "py -3" }

$backend = Join-Path $root "patchproof-remediation\patchproof"
$person1 = Join-Path $root "person1"
$frontend = Join-Path $root "frontend"

function Start-Svc($title, $cwd, $cmd) {
  Start-Process powershell -ArgumentList @(
    "-NoExit", "-ExecutionPolicy", "Bypass", "-Command",
    "`$host.UI.RawUI.WindowTitle='$title'; Set-Location '$cwd'; `$env:PYTHONIOENCODING='utf-8'; $cmd"
  )
}

Write-Host "Starting Person 2 backend (:8000)..."
Start-Svc "PATCHPROOF Backend :8000" $backend "$py -m uvicorn api:app --app-dir patch-engine --port 8000"

Write-Host "Starting Person 1 scanner API (:8100)..."
Start-Svc "PATCHPROOF Scanner :8100" $person1 "`$env:PATCHPROOF_PROJECT='$backend'; $py -m uvicorn scanner.api:app --port 8100"

Write-Host "Starting Person 3 frontend (:5173)..."
Start-Svc "PATCHPROOF Frontend :5173" $frontend "npm.cmd run dev"

Write-Host ""
Write-Host "All three services are launching in separate windows."
Write-Host "Open http://localhost:5173 once the frontend prints 'ready'."
