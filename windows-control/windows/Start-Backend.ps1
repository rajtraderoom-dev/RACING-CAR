. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  if (-not (Test-Path '.env')) { & "$PSScriptRoot\Setup-Windows.ps1"; exit $LASTEXITCODE }
  Run-Docker compose up -d --wait db
  Run-Docker compose --profile setup run --rm init
  Run-Docker compose up -d api gateway
  Write-Host 'Open https://localhost:8443/control/' -ForegroundColor Cyan
  Start-Process 'https://localhost:8443/control/'
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
