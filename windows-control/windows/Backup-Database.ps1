. "$PSScriptRoot\Common.ps1"
try {
  Assert-Docker
  $folder=Join-Path $ProjectRoot 'backups'; New-Item -ItemType Directory -Force -Path $folder | Out-Null
  $destination=Join-Path $folder ('racing-speed-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.dump')
  Run-Docker compose exec -T db pg_dump -U migration_owner -d racing_speed_control -Fc -f /tmp/racing-speed-backup.dump
  Run-Docker compose cp 'db:/tmp/racing-speed-backup.dump' $destination
  Run-Docker compose exec -T db rm -f /tmp/racing-speed-backup.dump
  Protect-LocalFile $destination
  Write-Host "Backup saved: $destination" -ForegroundColor Green
  Write-Host 'Copy it to your approved encrypted backup location. Financial backups are not encrypted by pg_dump itself.'
} catch { Write-Host $_.Exception.Message -ForegroundColor Red; exit 1 }
