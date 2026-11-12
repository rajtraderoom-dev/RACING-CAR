. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  Write-Host 'LOCAL OPERATOR RECOVERY - SUPER ADMIN' -ForegroundColor Yellow
  Write-Host 'This is a break-glass action for the Windows/Docker owner. It revokes the selected administrator''s old browser keys and sessions, optionally resets the app PIN, and writes an audit event.'
  $email=Read-Host 'Existing Super Admin email'
  $reason=Read-Host 'Recovery reason (at least 8 characters)'
  if ($reason.Trim().Length -lt 8) { throw 'A meaningful recovery reason is required.' }
  if ((Read-Host 'Type RECOVER to continue') -cne 'RECOVER') { throw 'Recovery cancelled.' }
  $secret=Read-Host 'New app PIN (6-12 digits), or press Enter to keep the current PIN' -AsSecureString
  $newPin=$null
  if ($secret.Length -gt 0) {
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try { $newPin=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($newPin -notmatch '^\d{6,12}$') { throw 'The PIN must contain 6-12 digits.' }
  }
  $payload=@{email=$email.Trim();reason=$reason;newPin=$newPin} | ConvertTo-Json -Compress
  $payload | & docker compose exec -T api node dist/recover-local.js
  if ($LASTEXITCODE -ne 0) { throw 'Recovery failed. Check that the server is running and the email is a Super Admin account.' }
  $payload=$null; $newPin=$null; $secret.Dispose()
  Write-Host 'Copy the enrollmentUrl above into Edge/Chrome on this computer. It expires in 24 hours and still requires the account PIN.' -ForegroundColor Green
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
