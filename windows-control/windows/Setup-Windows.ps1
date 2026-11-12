. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  Write-Host "`nRACING SPEED - WINDOWS LOCAL SETUP" -ForegroundColor Cyan
  Write-Host 'Creates a separate PostgreSQL database, API, and browser control panel. Test cash only.'
  $environment = Join-Path $ProjectRoot '.env'
  $codePath = Join-Path $ProjectRoot '.setup-code.txt'
  if (-not (Test-Path $environment)) {
    $ownerPassword=New-Secret; $appPassword=New-Secret; $jwt=New-Secret; $code=New-Secret
    $sha=[System.Security.Cryptography.SHA256]::Create()
    try { $codeHash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($code))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    @("DB_OWNER_PASSWORD=$ownerPassword","DB_APP_PASSWORD=$appPassword","JWT_SECRET=$jwt","BOOTSTRAP_TOKEN_HASH=$codeHash") | Set-Content -Encoding ASCII $environment
    $code | Set-Content -Encoding ASCII $codePath
    Protect-LocalFile $environment; Protect-LocalFile $codePath
    Write-Host 'Generated private local secrets. They are never uploaded to GitHub.'
  } else { Write-Host 'Existing configuration found; retaining credentials and database.' }
  Run-Docker compose up -d --wait db
  Run-Docker compose build api
  Run-Docker compose --profile setup run --rm init
  Run-Docker compose up -d api gateway
  & "$PSScriptRoot\Trust-Local-Certificate.ps1"
  if ($LASTEXITCODE -ne 0) { throw 'Certificate setup did not finish. Read the instructions above.' }
  Write-Host "`nCONTROL PANEL: https://localhost:8443/control/" -ForegroundColor Green
  if (Test-Path $codePath) {
    Write-Host 'First-run setup code (works only before the first Super Admin is enrolled):' -ForegroundColor Yellow
    Write-Host ((Get-Content -Raw $codePath).Trim())
    Write-Host 'Paste this code into the setup screen. Choose your own PIN and enroll Windows Hello/passkey.'
  }
  Start-Process 'https://localhost:8443/control/'
  Write-Host 'Done. Docker Desktop must remain running while you use the app.'
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
