# Packs this PC's OpenClaw state for the GCP VM, and stops the Windows gateway
# so only one bot is connected to Discord. Run in PowerShell on the Windows PC:
#   powershell -ExecutionPolicy Bypass -File deploy\gcp\export-state.ps1
#
# The archive contains the Discord token, API keys, and database password.
# Copy it to the VM over SSH only, and delete it from both machines afterwards.

$ErrorActionPreference = "Stop"

$state = Join-Path $env:USERPROFILE ".openclaw"
$staging = Join-Path $env:TEMP "openclaw-export"
$archive = Join-Path $env:USERPROFILE "openclaw-state.tgz"
$taskName = "OpenClaw Gateway"

if (-not (Test-Path $state)) {
    throw "No OpenClaw state found at $state"
}

Write-Host "==> Stopping the Windows gateway"
# Two gateways with one bot token would answer every chat message twice.
& openclaw gateway stop
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($task) {
    # Disabled, not deleted: re-enable with Enable-ScheduledTask to move back.
    Disable-ScheduledTask -TaskName $taskName | Out-Null
    Write-Host "Scheduled task '$taskName' disabled, so it will not start after a reboot."
}

Write-Host "==> Copying state (without Windows-only files)"
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Path $staging | Out-Null

# npm: Discord plugin packages with Windows-built parts; the VM reinstalls them.
# logs, backups, and the Windows service launchers are not needed.
& robocopy $state (Join-Path $staging ".openclaw") /E /NFL /NDL /NJH /NJS /NP `
    /XD npm logs `
    /XF gateway.cmd gateway.vbs "openclaw.json.bak*" | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed with exit code $LASTEXITCODE" }

Write-Host "==> Adding the database settings to the gateway's .env"
# On Windows these are user environment variables; on the VM the gateway reads ~/.openclaw/.env.
$envFile = Join-Path $staging ".openclaw\.env"
$names = "THREATINTEL_DB_HOST", "THREATINTEL_DB_PORT", "THREATINTEL_DB_NAME", "THREATINTEL_DB_USER", "THREATINTEL_DB_PASSWORD", "THREATINTEL_DB_SSL", "THREATINTEL_DB_SSL_CA"
$lines = @()
foreach ($name in $names) {
    $value = [Environment]::GetEnvironmentVariable($name, "User")
    if ($value) { $lines += "$name=$value" }
}
if ($lines.Count -lt 5) { throw "Expected at least THREATINTEL_DB_HOST, _PORT, _NAME, _USER and _PASSWORD in your user environment." }
# LF line endings, as Linux expects.
$existing = if (Test-Path $envFile) { (Get-Content $envFile -Raw) -replace "`r`n", "`n" } else { "" }
if ($existing -and -not $existing.EndsWith("`n")) { $existing += "`n" }
[IO.File]::WriteAllText($envFile, $existing + ($lines -join "`n") + "`n")

Write-Host "==> Creating $archive"
if (Test-Path $archive) { Remove-Item -Force $archive }
& tar -czf $archive -C $staging .openclaw
if ($LASTEXITCODE -ne 0) { throw "tar failed" }
Remove-Item -Recurse -Force $staging

$size = [math]::Round((Get-Item $archive).Length / 1MB, 1)
Write-Host ""
Write-Host "Done: $archive ($size MB)."
Write-Host "It contains secrets. Copy it to the VM over SSH, for example:"
Write-Host "  gcloud compute scp `"$archive`" threatintel-gateway:~/ --zone=us-central1-a"
Write-Host "then delete it here."
Write-Host ""
Write-Host "To move back to this PC instead: Enable-ScheduledTask -TaskName '$taskName'; openclaw gateway restart"
