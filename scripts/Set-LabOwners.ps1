param([switch]$Apply)

# Metadata-only change inside the existing lab OU. Run without -Apply first.
# AD user objects support manager; managedBy is not writable on this schema.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
if ((Get-ADDomain).DNSRoot -ne 'infraradar.test' -or $env:COMPUTERNAME -ne 'INFRARADAR-DC01') {
    throw 'Unexpected domain controller'
}
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop
$users = @(Get-ADUser -SearchBase $labOu -Filter * -Properties Manager)
if ($users.Count -notin @(42, 43) -or
    ($users.Count -eq 43 -and 'adm.t.zhaksybek' -notin $users.SamAccountName)) {
    throw "Unexpected lab account inventory: $($users.Count)"
}
$bySam = @{}
foreach ($user in $users) { $bySam[$user.SamAccountName] = $user }

# An existing line manager is the preferred responsible person. The remaining
# admin, service, reader and team lead identities have explicit lab owners.
$ownerBySam = @{
    'a.sadykov' = 's.aliyeva'
    'a.orynbek' = 'a.sadykov'
    'd.iskakov' = 'a.sadykov'
    'm.nurgaliyev' = 'a.sadykov'
    'n.tulegenov' = 'a.sadykov'
    's.aliyeva' = 'a.sadykov'
    'z.akhmetova' = 'a.sadykov'
    'adm.a.kassymova' = 'a.kassymova'
    'adm.a.sadykov' = 'a.sadykov'
    'adm.d.iskakov' = 'd.iskakov'
    'adm.e.ivanov' = 'e.ivanov'
    'adm.m.nurgaliyev' = 'm.nurgaliyev'
    'adm.r.saparov' = 'r.saparov'
    'adm.t.karimov' = 'a.sadykov'
    'adm.t.zhaksybek' = 'a.sadykov'
    'ir-event-reader' = 'a.sadykov'
    'ir-ldap-reader' = 'a.sadykov'
    'svc_1c' = 'm.nurgaliyev'
    'svc_backup' = 'a.sadykov'
    'svc_exchange' = 'a.sadykov'
    'svc_iis' = 'a.sadykov'
    'svc_monitoring' = 's.aliyeva'
    'svc_sql' = 'a.sadykov'
    'svc_web' = 'a.sadykov'
}
$plan = @()
foreach ($user in $users) {
    $ownerDn = if ($user.Manager) { $user.Manager } else {
        $ownerSam = $ownerBySam[$user.SamAccountName]
        if (-not $ownerSam -or -not $bySam.ContainsKey($ownerSam)) {
            throw "No verified lab owner for $($user.SamAccountName)"
        }
        $bySam[$ownerSam].DistinguishedName
    }
    if ($ownerDn -notlike "*,$labOu" -or $ownerDn -eq $user.DistinguishedName) {
        throw "Owner is outside lab OU or equals account: $($user.SamAccountName)"
    }
    $owner = Get-ADUser -Identity $ownerDn -ErrorAction Stop
    if (-not $bySam.ContainsKey($owner.SamAccountName)) {
        throw "Owner is not among the verified lab accounts: $($user.SamAccountName)"
    }
    $plan += [pscustomobject]@{
        User = $user.SamAccountName
        UserDn = $user.DistinguishedName
        Owner = $owner.SamAccountName
        OwnerDn = $ownerDn
        NeedsUpdate = ($user.Manager -ne $ownerDn)
    }
}
if ($Apply) {
    foreach ($row in $plan | Where-Object NeedsUpdate) {
        Set-ADUser -Identity $row.UserDn -Manager $row.OwnerDn
    }
}
[pscustomobject]@{
    Mode = if ($Apply) { 'APPLIED' } else { 'DRY_RUN' }
    LabUsers = $plan.Count
    Updates = @($plan | Where-Object NeedsUpdate).Count
    Owners = @($plan | Select-Object -ExpandProperty Owner -Unique).Count
    Domain = 'infraradar.test'
    LabOU = $labOu
} | ConvertTo-Json -Compress
