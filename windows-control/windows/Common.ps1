$ErrorActionPreference = 'Stop'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $ProjectRoot
function Run-Docker {
  & docker @args
  if ($LASTEXITCODE -ne 0) { throw 'Docker command failed. Read the message above. Check that Docker Desktop is running with Linux containers.' }
}
function Assert-Docker {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install Docker Desktop for Windows, enable WSL 2/Linux containers, then run this script again.' }
  $server = & docker version --format '{{.Server.Os}}' 2>$null
  if ($LASTEXITCODE -ne 0 -or $server -ne 'linux') { throw 'Start Docker Desktop and select Linux containers. Wait until its engine is running.' }
  & docker compose version | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Docker Compose is missing. Update Docker Desktop.' }
}
function New-Secret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return [BitConverter]::ToString($bytes).Replace('-','').ToLowerInvariant()
}
function Protect-LocalFile([string]$Path) {
  if (Test-Path $Path) {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & icacls $Path /inheritance:r /grant:r "*$($sid):(F)" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not tighten permissions on $Path. Keep this file private." }
  }
}
function Wait-LocalCertificate {
  New-Item -ItemType Directory -Force -Path (Join-Path $ProjectRoot 'runtime') | Out-Null
  $certificate = Join-Path $ProjectRoot 'runtime\local-test-ca.crt'
  for ($attempt=0; $attempt -lt 30; $attempt++) {
    & docker compose cp 'gateway:/data/caddy/pki/authorities/local/root.crt' $certificate 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $certificate)) { return $certificate }
    Start-Sleep -Seconds 1
  }
  throw 'The local TLS certificate was not created. Run docker compose logs gateway and check port 8443.'
}
