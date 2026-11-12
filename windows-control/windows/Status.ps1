. "$PSScriptRoot\Common.ps1"
try { Assert-Docker; Run-Docker compose ps; Write-Host 'Panel URL: https://localhost:8443/control/'; Write-Host 'For logs: docker compose logs --tail 80 api gateway' } catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
