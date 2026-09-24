# Run on INFRARADAR-DC01. Creates only objects inside the existing lab OU.
# Re-running does not reset passwords or duplicate users, groups, or memberships.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory

$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'infraradar.test') { throw 'Unexpected AD domain' }
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop

function Assert-LabObject($object) {
    if ($object.DistinguishedName -notlike "*,$labOu") {
        throw "Object is outside the lab OU: $($object.DistinguishedName)"
    }
}

function Ensure-LabGroup([string]$name) {
    try { $group = Get-ADGroup -Identity $name -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $group = $null }
    if ($group) { Assert-LabObject $group; return $group }
    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path $labOu
    return Get-ADGroup -Identity $name
}

function New-RandomPassword {
    $bytes = New-Object byte[] 30
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    ConvertTo-SecureString -String (([Convert]::ToBase64String($bytes)) + 'aA1!') -AsPlainText -Force
}

function Ensure-LabUser([string]$sam, [string]$name) {
    try { $user = Get-ADUser -Identity $sam -ErrorAction Stop }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { $user = $null }
    if ($user) { Assert-LabObject $user; return $user }
    New-ADUser -Name $name -DisplayName $name -SamAccountName $sam `
        -UserPrincipalName "$sam@infraradar.test" -Path $labOu -Enabled $true `
        -AccountPassword (New-RandomPassword) -ChangePasswordAtLogon $false
    return Get-ADUser -Identity $sam
}

function Ensure-LabMembership([string]$groupName, [string]$memberName) {
    $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
    Assert-LabObject $group
    $member = Get-ADObject -LDAPFilter "(sAMAccountName=$memberName)" -SearchBase $labOu -ErrorAction Stop
    if (-not $member) { throw "Missing lab member: $memberName" }
    Assert-LabObject $member
    $direct = @(Get-ADGroupMember -Identity $group.DistinguishedName | Select-Object -ExpandProperty DistinguishedName)
    if ($member.DistinguishedName -notin $direct) {
        Add-ADGroupMember -Identity $group.DistinguishedName -Members $member.DistinguishedName
    }
}

function Ensure-Service([string]$sam, [string]$spn, [bool]$nonExpiring) {
    $user = Ensure-LabUser $sam "IR Service $sam"
    $current = Get-ADUser -Identity $user.DistinguishedName -Properties ServicePrincipalName,PasswordNeverExpires
    if ($spn -notin @($current.ServicePrincipalName)) {
        Set-ADUser -Identity $user.DistinguishedName -ServicePrincipalNames @{Add=$spn}
    }
    if ($nonExpiring -and -not $current.PasswordNeverExpires) {
        Set-ADUser -Identity $user.DistinguishedName -PasswordNeverExpires $true
    }
}

# These groups live inside the lab OU. IR-Lab-Admins receives delegated control
# only over this OU and its descendants, making nested membership a real lab risk.
@('IR-Lab-Admins', 'IR-Helpdesk', 'IR-Infrastructure', 'IR-Service-Ops', 'IR-Audit') |
    ForEach-Object { $null = Ensure-LabGroup $_ }

$labAdminSid = (Get-ADGroup -Identity 'IR-Lab-Admins').SID
$aclPath = "AD:\$labOu"
$acl = Get-Acl -Path $aclPath
$hasDelegation = @($acl.Access | Where-Object {
    ($_.IdentityReference.Value -eq $labAdminSid.Value -or
     $_.IdentityReference.Value -like '*\IR-Lab-Admins') -and
    (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0)
}).Count -gt 0
if (-not $hasDelegation) {
    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $labAdminSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $aclPath -AclObject $acl
}

Ensure-LabMembership 'IR-Lab-Admins' 'IR-Infrastructure'
Ensure-LabMembership 'IR-Infrastructure' 'IR-Helpdesk'
Ensure-LabMembership 'IR-Infrastructure' 'IR-Service-Ops'
Ensure-LabMembership 'IR-Lab-Admins' 'IR-Nested-Risk'

# Healthy control accounts. New passwords are random, never printed or stored.
1..9 | ForEach-Object {
    $sam = 'ir-demo-{0:d2}' -f $_
    $null = Ensure-LabUser $sam ('IR Demo User {0:d2}' -f $_)
    Ensure-LabMembership 'IR-Audit' $sam
}

Ensure-Service 'ir-svc-backup' 'IRBackup/backup.infraradar.test' $true
Ensure-Service 'ir-svc-sync' 'IRSync/sync.infraradar.test' $true
Ensure-Service 'ir-svc-monitor' 'IRMonitor/monitor.infraradar.test' $false
Ensure-Service 'ir-svc-report' 'IRReport/report.infraradar.test' $false
Ensure-Service 'ir-svc-deploy' 'IRDeploy/deploy.infraradar.test' $true

Ensure-LabMembership 'IR-Service-Ops' 'ir-svc-backup'
Ensure-LabMembership 'IR-Helpdesk' 'ir-svc-sync'
Ensure-LabMembership 'IR-Audit' 'ir-svc-monitor'
Ensure-LabMembership 'IR-Audit' 'ir-svc-report'
Ensure-LabMembership 'IR-Audit' 'ir-svc-deploy'

$null = Ensure-LabUser 'ir-demo-expired2' 'IR Demo Expired 2'
$expired = Get-ADUser 'ir-demo-expired2' -Properties AccountExpirationDate
if (-not $expired.AccountExpirationDate -or $expired.AccountExpirationDate -gt (Get-Date)) {
    Set-ADAccountExpiration -Identity $expired.DistinguishedName -DateTime (Get-Date).AddDays(-2)
}

@('ir-dis-admin1', 'ir-dis-admin2') | ForEach-Object {
    $user = Ensure-LabUser $_ ('IR Demo Disabled Admin ' + $_)
    if ($user.Enabled) { Disable-ADAccount -Identity $user.DistinguishedName }
    Ensure-LabMembership 'IR-Lab-Admins' $_
}

# Existing lab users gain only membership in a lab group. No built-in group is changed.
Ensure-LabMembership 'IR-Lab-Admins' 'ir-disabled'
Ensure-LabMembership 'IR-Lab-Admins' 'ir-domainadmin'
Ensure-LabMembership 'IR-Lab-Admins' 'ir-multirisk'
Ensure-LabMembership 'IR-Helpdesk' 'ir-carol'

[pscustomobject]@{
    TestUsers = @(Get-ADUser -SearchBase $labOu -Filter *).Count
    TestGroups = @(Get-ADGroup -SearchBase $labOu -Filter *).Count
    LabOU = $labOu
} | ConvertTo-Json -Compress
