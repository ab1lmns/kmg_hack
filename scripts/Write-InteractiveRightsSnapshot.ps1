# Scheduled on the test DC as LocalSystem. Exports effective rights without
# changing the policy, then replaces a reader-accessible JSON snapshot.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ne 'INFRARADAR-DC01') { throw 'Unexpected host' }
$directory = 'C:\ProgramData\InfraRadarLab'
$exportScript = Join-Path $directory 'Export-InteractiveRights.ps1'
if (-not (Test-Path $exportScript)) { throw 'Exporter missing' }
$json = & $exportScript
$payload = $json | ConvertFrom-Json
if ($payload.target_host -ne $env:COMPUTERNAME -or
    @($payload.token_sids.PSObject.Properties).Count -lt 7 -or
    @($payload.rights.PSObject.Properties).Count -ne 4) {
    throw 'Incomplete interactive-rights export'
}
$target = Join-Path $directory 'interactive-rights.json'
$temporary = Join-Path $directory ('interactive-rights-' + [guid]::NewGuid().ToString() + '.tmp')
try {
    [System.IO.File]::WriteAllText($temporary, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $target -Force
} finally {
    Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue
}
