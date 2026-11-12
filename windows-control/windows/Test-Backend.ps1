. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  Write-Host 'Tests use separate temporary databases. Your control-panel database is not touched.' -ForegroundColor Cyan
  & docker compose -f compose.tests.yaml up --build --abort-on-container-exit --exit-code-from tests
  $result=$LASTEXITCODE
  & docker compose -f compose.tests.yaml down -v
  if ($result -ne 0) { throw 'Tests did not pass. Review the output above.' }
  Write-Host 'Backend test suite passed.' -ForegroundColor Green
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
