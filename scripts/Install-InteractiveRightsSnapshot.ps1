param([switch]$Apply)

# Run on the test DC after copying Export-InteractiveRights.ps1 and
# Write-InteractiveRightsSnapshot.ps1 to C:\ProgramData\InfraRadarLab.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
if ($env:COMPUTERNAME -ne 'INFRARADAR-DC01' -or (Get-ADDomain).DNSRoot -ne 'infraradar.test') {
    throw 'Unexpected domain controller'
}
$directory = 'C:\ProgramData\InfraRadarLab'
$taskName = 'InfraRadar-InteractiveRights-ReadOnlyExport'
$reader = Get-ADUser -Identity 'ir-event-reader' -ErrorAction Stop
if ($reader.DistinguishedName -notlike '*,OU=InfraRadarLab,DC=infraradar,DC=test') {
    throw 'Reader is outside lab OU'
}
$required = @('Export-InteractiveRights.ps1','Write-InteractiveRightsSnapshot.ps1')
foreach ($name in $required) {
    if (-not (Test-Path (Join-Path $directory $name))) { throw "Missing script: $name" }
}
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing -and $existing.Principal.UserId -ne 'SYSTEM' -and
    $existing.Principal.UserId -ne 'S-1-5-18') { throw 'Task exists with unexpected principal' }
if (-not $Apply) {
    [pscustomobject]@{Mode='DRY_RUN';Task=$taskName;Folder=$directory;
        Reader=$reader.SamAccountName;Existing=[bool]$existing} | ConvertTo-Json -Compress
    return
}

# Remove inherited access only from our new collector folder. Grant the
# dedicated reader read access; no admin credential is stored in backend.
$acl = Get-Acl -LiteralPath $directory
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $null = $acl.RemoveAccessRuleSpecific($_) }
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$propagate = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($entry in @(
    @('S-1-5-18',[System.Security.AccessControl.FileSystemRights]::FullControl),
    @('S-1-5-32-544',[System.Security.AccessControl.FileSystemRights]::FullControl),
    @($reader.SID.Value,[System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
)) {
    $sid = [System.Security.Principal.SecurityIdentifier]::new($entry[0])
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $sid, $entry[1], $inherit, $propagate, $allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $directory -AclObject $acl
foreach ($name in $required) {
    $file = Join-Path $directory $name
    $fileAcl = Get-Acl -LiteralPath $file
    $fileAcl.SetAccessRuleProtection($false, $true)
    Set-Acl -LiteralPath $file -AclObject $fileAcl
}
$writer = Join-Path $directory 'Write-InteractiveRightsSnapshot.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $writer + '"')
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
for ($attempt = 0; $attempt -lt 90; $attempt++) {
    Start-Sleep -Seconds 1
    $target = Join-Path $directory 'interactive-rights.json'
    if (Test-Path $target) {
        $payload = Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
        $collectedUtc = [datetimeoffset]::Parse([string]$payload.collected_at).UtcDateTime
        $ageMinutes = ((Get-Date).ToUniversalTime() - $collectedUtc).TotalMinutes
        if ($payload.target_host -eq $env:COMPUTERNAME -and
            $ageMinutes -ge 0 -and $ageMinutes -lt 2) {
            [pscustomobject]@{Mode='APPLIED';Task=$taskName;Reader=$reader.SamAccountName;
                Target=$payload.target_host;TokenCount=@($payload.token_sids.PSObject.Properties).Count} |
                ConvertTo-Json -Compress
            return
        }
    }
}
throw 'Scheduled export did not produce a fresh snapshot'
