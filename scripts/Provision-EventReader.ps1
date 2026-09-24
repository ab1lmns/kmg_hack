# Run on the test DC only. $PublicKey is supplied by the Mac launcher.
# Makes a non-admin lab identity with the existing Event Log Readers read ACE.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
if (-not $PublicKey -or $PublicKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?:\s+[^\r\n]*)?$') {
    throw 'A valid ed25519 public key is required'
}
$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'infraradar.test') { throw 'Unexpected domain' }
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop
$securityAcl = (& wevtutil gl Security | Select-String '^channelAccess:').ToString()
if ($securityAcl -notmatch '\(A;;0x1;;;S-1-5-32-573\)') {
    throw 'Security log does not grant read-only access to Event Log Readers; no changes made'
}
$name = 'ir-event-reader'
$user = Get-ADUser -LDAPFilter "(sAMAccountName=$name)" -Properties MemberOf,Enabled -ErrorAction Stop
if (-not $user) {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $password = ConvertTo-SecureString (([Convert]::ToBase64String($bytes)) + 'aA1!') -AsPlainText -Force
    New-ADUser -Name 'IR Event Reader' -SamAccountName $name -Path $labOu `
        -UserPrincipalName "$name@infraradar.test" -AccountPassword $password `
        -Enabled $true -PasswordNeverExpires $true -AccountNotDelegated $true `
        -Description 'InfraRadar lab read-only Security Event Log collector'
    $user = Get-ADUser -Identity $name -Properties MemberOf,Enabled
}
if ($user.DistinguishedName -notlike "*,$labOu") { throw 'Existing user is outside the lab OU' }
if (-not $user.Enabled) { throw 'Existing event reader is disabled; no changes made' }
$group = Get-ADGroup -Identity 'Event Log Readers' -Properties Members
if ($group.SID.Value -ne 'S-1-5-32-573') { throw 'Unexpected Event Log Readers group' }
if ($user.DistinguishedName -notin @($group.Members)) {
    Add-ADGroupMember -Identity $group -Members $user
}
$privileged = @(Get-ADPrincipalGroupMembership -Identity $user | Where-Object {
    $_.SID.Value -match '^S-1-5-32-(544|548|549|550|551|552)$' -or
    $_.SID.Value -match '^S-1-5-21-[0-9-]+-(512|518|519)$'
})
if ($privileged.Count) { throw 'Event reader has privileged group membership; no key installed' }
$profileInfo = Get-CimInstance Win32_UserProfile | Where-Object SID -eq $user.SID.Value
if (-not $profileInfo) {
    # Windows may append the domain name to the profile directory. Ask the
    # profile API to create it and use its returned path rather than guessing.
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class EventReaderProfile {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int CreateProfile(string sid, string name, StringBuilder path, uint length);
}
'@
    $buffer = New-Object System.Text.StringBuilder 512
    $hr = [EventReaderProfile]::CreateProfile($user.SID.Value, $name, $buffer, 512)
    if ($hr -ne 0) { throw "CreateProfile failed with HRESULT $hr" }
    $profile = $buffer.ToString()
} else {
    $profile = $profileInfo.LocalPath
}
if (-not $profile -or -not (Test-Path $profile)) { throw 'Event reader profile path not found' }
$sshDir = Join-Path $profile '.ssh'
$authorized = Join-Path $sshDir 'authorized_keys'
$null = New-Item -ItemType Directory -Path $sshDir -Force
Set-Content -Path $authorized -Value $PublicKey.Trim() -Encoding ascii
$sid = $user.SID.Value
foreach ($path in @($profile, $sshDir)) {
    & icacls.exe $path /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to restrict ACL on $path" }
}
& icacls.exe $authorized /inheritance:r /grant:r "*${sid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict authorized_keys ACL' }
[pscustomobject]@{
    username = $user.SamAccountName
    dn = $user.DistinguishedName
    group_sid = $group.SID.Value
    security_log_read_ace = $true
    admin_member = $false
    key_type = 'ed25519'
} | ConvertTo-Json -Compress
