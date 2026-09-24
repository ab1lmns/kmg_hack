# Creates one disposable lab user and a PSO scoped only to that user.
# The PSO object must live in AD's Password Settings Container by design.
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'infraradar.test') { throw 'Unexpected domain' }
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop
$sam = 'ir-lockout-lab'
$user = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction Stop
if (-not $user) {
    $bytes = New-Object byte[] 30
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $password = ConvertTo-SecureString (([Convert]::ToBase64String($bytes)) + 'aA1!') -AsPlainText -Force
    New-ADUser -Name 'IR Lab Lockout' -SamAccountName $sam -Path $labOu `
        -UserPrincipalName "$sam@infraradar.test" -AccountPassword $password -Enabled $true
    $user = Get-ADUser -Identity $sam
}
if ($user.DistinguishedName -notlike "*,$labOu") { throw 'User is outside lab OU' }
$name = 'IR-Lab-Lockout-PSO'
$pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -ErrorAction Stop
if (-not $pso) {
    New-ADFineGrainedPasswordPolicy -Name $name -Precedence 10 `
        -ComplexityEnabled $true -MinPasswordLength 12 -PasswordHistoryCount 5 `
        -MinPasswordAge '0.00:00:00' -MaxPasswordAge '42.00:00:00' `
        -LockoutThreshold 3 -LockoutDuration '00:05:00' `
        -LockoutObservationWindow '00:05:00'
    $pso = Get-ADFineGrainedPasswordPolicy -Identity $name
}
if ($pso.LockoutThreshold -ne 3 -or $pso.Precedence -ne 10) {
    throw 'Existing PSO differs from expected lab settings; no changes made'
}
$subjects = @(Get-ADFineGrainedPasswordPolicy -Identity $name -Properties AppliesTo | Select-Object -ExpandProperty AppliesTo)
if ($user.DistinguishedName -notin $subjects) {
    Add-ADFineGrainedPasswordPolicySubject -Identity $name -Subjects $user.DistinguishedName
}
# Default PSO ACL is admin-only on this lab DC. Grant read on this PSO object
# to the scanner, without changing the container or any other policy.
$reader = Get-ADUser -Identity 'ir-ldap-reader' -ErrorAction Stop
$aclPath = "AD:\$($pso.DistinguishedName)"
$acl = Get-Acl $aclPath
$hasReaderRead = @($acl.Access | Where-Object {
    ($_.IdentityReference.Value -eq $reader.SID.Value -or
     $_.IdentityReference.Value -like '*\ir-ldap-reader') -and
    (($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) -ne 0)
}).Count -gt 0
if (-not $hasReaderRead) {
    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $reader.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl $aclPath $acl
}
$resultant = Get-ADUserResultantPasswordPolicy -Identity $user.DistinguishedName
[pscustomobject]@{
    User = $user.SamAccountName
    UserDN = $user.DistinguishedName
    Policy = $resultant.Name
    Threshold = $resultant.LockoutThreshold
    Scope = 'single lab user'
} | ConvertTo-Json -Compress
