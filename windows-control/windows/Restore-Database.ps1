param([string]$BackupFile)
. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  if (-not $BackupFile) { $BackupFile=Read-Host 'Full path to the .dump backup file' }
  $fullPath=(Resolve-Path -LiteralPath $BackupFile).Path
  if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw 'Backup file not found.' }
  Write-Host "Restore source: $fullPath" -ForegroundColor Yellow
  Write-Host 'This replaces the local database. The API will stop during restore. Keep a backup of current data first.'
  if ((Read-Host 'Type RESTORE to continue') -cne 'RESTORE') { throw 'Restore cancelled.' }
  Run-Docker compose stop api
  Run-Docker compose cp $fullPath 'db:/tmp/racing-speed-restore.dump'
  Run-Docker compose exec -T db pg_restore --clean --if-exists --no-owner --no-acl --exit-on-error -U migration_owner -d racing_speed_control /tmp/racing-speed-restore.dump
  Run-Docker compose exec -T db rm -f /tmp/racing-speed-restore.dump
  Run-Docker compose --profile setup run --rm init
  Run-Docker compose up -d api gateway
  Write-Host 'Restore completed. Verify audit checkpoints and account/device access before resuming.' -ForegroundColor Green
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; Write-Host 'If restore failed, the API may remain stopped. Diagnose the database before restarting.'; exit 1 }
