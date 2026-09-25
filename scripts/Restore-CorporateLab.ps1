param([switch]$Apply)

# Reconcile only the current fictional InfraRadarLab users. Dry run by default.
# Existing passwords, memberships, risk flags and timestamps are never changed.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
if ($env:COMPUTERNAME -ne 'INFRARADAR-DC01' -or (Get-ADDomain).DNSRoot -ne 'infraradar.test') {
    throw 'Unexpected domain controller'
}
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop
$company = 'Northbridge Digital KZ'

# sam, given name, surname, department, title, manager sam
$people = @(
    @('z.akhmetova','Zarina','Akhmetova','HR','HR Manager','n.serikova'),
    @('a.orynbek','Asel','Orynbek','Legal','Legal Counsel','e.kim'),
    @('n.tulegenov','Nurlan','Tulegenov','Sales','Sales Manager','t.akhmetov'),
    @('s.aliyeva','Saltanat','Aliyeva','Security','Security Analyst','r.ibrayev'),
    @('e.ivanov','Erik','Ivanov','IT','Infrastructure Engineer','d.iskakov'),
    @('r.saparov','Rustem','Saparov','Operations','Operations Supervisor','t.akhmetov'),
    @('k.zhumabek','Kairat','Zhumabek','Finance','Accountant','a.sadykov'),
    @('l.serikova','Laura','Serikova','Sales','Sales Operations Specialist','n.tulegenov'),
    @('b.askarov','Bolat','Askarov','Legal','Compliance Analyst','e.kim'),
    @('g.nazarova','Gulmira','Nazarova','HR','HR Specialist','n.serikova'),
    @('m.kalayeva','Madina','Kalayeva','HR','HR Coordinator','n.serikova'),
    @('t.ibrayeva','Tamara','Ibrayeva','Finance','Treasury Analyst','a.sadykov'),
    @('p.kuandykova','Perizat','Kuandykova','Operations','Procurement Specialist','t.akhmetov'),
    @('i.zhaksylykov','Ilyas','Zhaksylykov','IT','Software Engineer','d.iskakov')
)
$ownerForExisting = @{
    'ir-ldap-reader' = 'a.sadykov'
    'ir-event-reader' = 'r.ibrayev'
    'a.sadykov' = 'd.iskakov'
    'd.iskakov' = 'a.sadykov'
    'n.serikova' = 'd.iskakov'
    't.akhmetov' = 'd.iskakov'
    'e.kim' = 'a.sadykov'
    'adm.d.iskakov' = 'd.iskakov'
    'adm.t.zhaksybek' = 'd.iskakov'
}
$ownerForNew = @{}
foreach ($row in $people) { $ownerForNew[$row[0]] = $row[5] }
$current = @(Get-ADUser -SearchBase $labOu -Filter * -Properties Manager)
if ($current.Count -notin @(28,42)) { throw "Unexpected lab user count: $($current.Count)" }
$bySam = @{}
foreach ($user in $current) { $bySam[$user.SamAccountName] = $user }
foreach ($name in @('adm.a.sadykov','svc_backup','ir-ldap-reader','ir-event-reader')) {
    if (-not $bySam.ContainsKey($name)) { throw "Required lab account missing: $name" }
}
$newNames = @($people | ForEach-Object { $_[0] })
if (@($newNames | Select-Object -Unique).Count -ne $people.Count) { throw 'Duplicate planned username' }
$missing = @()
foreach ($row in $people) {
    $sam = $row[0]
    $anywhere = Get-ADUser -LDAPFilter "(sAMAccountName=$sam)"
    if ($anywhere -and $anywhere.DistinguishedName -notlike "*,$labOu") {
        throw "Planned username exists outside lab OU: $sam"
    }
    if (-not $anywhere) {
        $display = "$($row[1]) $($row[2])"
        if (Get-ADObject -SearchBase $labOu -LDAPFilter "(cn=$display)") {
            throw "Planned CN already exists in lab OU: $display"
        }
        $missing += $sam
    }
}
if ($current.Count + $missing.Count -ne 42) {
    throw "Unexpected resulting lab inventory: $($current.Count) + $($missing.Count)"
}
$plannedNames = @($bySam.Keys) + $newNames
foreach ($name in @($ownerForExisting.Keys) + @($ownerForNew.Values)) {
    if ($name -notin $plannedNames) { throw "Manager is absent from lab plan: $name" }
}
$pso = Get-ADFineGrainedPasswordPolicy -Identity 'IR-Lab-Lockout-PSO' -ErrorAction Stop
$subjects = @(Get-ADFineGrainedPasswordPolicySubject -Identity $pso)
if (@($subjects | Where-Object { $_.SamAccountName -ne 'm.kalayeva' }).Count) {
    throw 'FGPP has an unexpected subject; refusing to alter it'
}
if (-not $Apply) {
    [pscustomobject]@{
        Mode='DRY_RUN'; LabOU=$labOu; Existing=$current.Count; Create=$missing;
        OwnersMissing=@($current | Where-Object { -not $_.Manager }).Count;
        FGPPSubjects=$subjects.Count; ExpectedAfter=42
    } | ConvertTo-Json -Depth 3 -Compress
    return
}

function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ConvertTo-SecureString (([Convert]::ToBase64String($bytes)) + 'aA1!') -AsPlainText -Force
}
foreach ($row in $people) {
    if ($row[0] -notin $missing) { continue }
    $sam,$given,$surname,$department,$title = $row[0..4]
    $display = "$given $surname"
    New-ADUser -Name $display -DisplayName $display -GivenName $given -Surname $surname `
        -SamAccountName $sam -UserPrincipalName "$sam@infraradar.test" `
        -Department $department -Title $title -Company $company `
        -Description "$title | $department | $company" -Path $labOu `
        -AccountPassword (New-RandomPassword) -Enabled $true
}
$after = @(Get-ADUser -SearchBase $labOu -Filter * -Properties Manager)
if ($after.Count -ne 42) { throw "Unexpected lab count after creation: $($after.Count)" }
$bySam = @{}
foreach ($user in $after) { $bySam[$user.SamAccountName] = $user }
$ownerUpdates = 0
foreach ($user in $after) {
    if ($user.Manager) { continue }
    $managerSam = if ($ownerForExisting.ContainsKey($user.SamAccountName)) {
        $ownerForExisting[$user.SamAccountName]
    } else { $ownerForNew[$user.SamAccountName] }
    if (-not $managerSam -or -not $bySam.ContainsKey($managerSam) -or
        $managerSam -eq $user.SamAccountName) {
        throw "No safe lab manager for $($user.SamAccountName)"
    }
    Set-ADUser -Identity $user.DistinguishedName -Manager $bySam[$managerSam].DistinguishedName
    $ownerUpdates++
}
if (-not $subjects.Count) {
    Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects $bySam['m.kalayeva'].DistinguishedName
}
$verified = @(Get-ADUser -SearchBase $labOu -Filter * -Properties Manager)
$resultant = Get-ADUserResultantPasswordPolicy -Identity 'm.kalayeva'
if (@($verified | Where-Object { -not $_.Manager }).Count -or
    -not $resultant -or $resultant.Name -ne $pso.Name) {
    throw 'Lab owner or resultant FGPP verification failed'
}
[pscustomobject]@{
    Mode='APPLIED'; LabUsers=$verified.Count; Created=$missing.Count;
    OwnerUpdates=$ownerUpdates; Owners=$verified.Count;
    FGPPUser='m.kalayeva'; ResultantPSO=$resultant.Name
} | ConvertTo-Json -Compress
