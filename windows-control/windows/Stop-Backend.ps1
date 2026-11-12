. "$PSScriptRoot\Common.ps1"
try { Assert-Docker; Run-Docker compose stop; Write-Host 'Backend stopped. Database and certificate volumes are retained.' -ForegroundColor Green } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
