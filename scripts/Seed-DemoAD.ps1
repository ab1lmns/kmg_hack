# Run only on INFRARADAR-DC01. Changes only accounts in InfraRadarLab.
# Migration preserves SID, password, memberships, SPNs and existing risk flags.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
if ((Get-ADDomain).DNSRoot -ne 'infraradar.test' -or $env:COMPUTERNAME -ne 'INFRARADAR-DC01') {
    throw 'Unexpected domain controller'
}
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$null = Get-ADOrganizationalUnit -Identity $labOu -ErrorAction Stop
$company = 'InfraRadar Group'

# Legacy name, target samAccountName, given name, surname, department, title, type.
$people = @(
    @('ir-alice','a.sadykov','Aidar','Sadykov','IT','Systems Engineer','employee'),
    @('ir-bob','d.iskakov','Daniyar','Iskakov','Operations','Operations Analyst','employee'),
    @('ir-carol','a.kassymova','Aigerim','Kassymova','IT','Helpdesk Specialist','employee'),
    @('ir-demo-01','m.nurgaliyev','Murat','Nurgaliyev','Finance','Financial Analyst','employee'),
    @('ir-demo-02','z.akhmetova','Zarina','Akhmetova','HR','HR Business Partner','employee'),
    @('ir-demo-03','a.orynbek','Asel','Orynbek','Legal','Legal Counsel','employee'),
    @('ir-demo-04','n.tulegenov','Nurlan','Tulegenov','Sales','Account Manager','employee'),
    @('ir-demo-05','s.aliyeva','Saltanat','Aliyeva','Security','Security Analyst','employee'),
    @('ir-demo-06','e.ivanov','Erik','Ivanov','IT','Infrastructure Engineer','employee'),
    @('ir-demo-07','r.saparov','Rustem','Saparov','Operations','Shift Supervisor','employee'),
    @('ir-demo-08','k.zhumabek','Kairat','Zhumabek','Finance','Accountant','employee'),
    @('ir-demo-09','l.serikova','Laura','Serikova','Sales','Sales Operations Specialist','employee'),
    @('ir-demo-expired2','b.askarov','Bolat','Askarov','Legal','Legal Specialist','employee'),
    @('ir-expired','g.nazarova','Gulmira','Nazarova','HR','HR Specialist','employee'),
    @('ir-lockout-lab','m.kalayeva','Madina','Kalayeva','HR','HR Coordinator','employee'),
    @('ir-noexpire','t.ibrayeva','Tamara','Ibrayeva','Finance','Treasury Analyst','employee'),
    @('ir-domainadmin','adm.a.sadykov','Aidar','Sadykov','IT','Domain Administrator','admin'),
    @('ir-multirisk','adm.d.iskakov','Daniyar','Iskakov','Operations','Operations Administrator','admin'),
    @('ir-disabled','adm.t.karimov','Timur','Karimov','IT','Former Administrator','admin'),
    @('ir-dis-admin1','adm.r.saparov','Rustem','Saparov','Operations','Former Administrator','admin'),
    @('ir-dis-admin2','adm.a.kassymova','Aigerim','Kassymova','IT','Former Helpdesk Administrator','admin'),
    @('ir-accountop','adm.m.nurgaliyev','Murat','Nurgaliyev','Finance','Account Operator','admin'),
    @('ir-serverop','adm.e.ivanov','Erik','Ivanov','IT','Server Operator','admin'),
    @($null,'p.kuandykova','Perizat','Kuandykova','Finance','Procurement Analyst','employee'),
    @($null,'a.bekov','Arman','Bekov','Sales','Sales Manager','employee'),
    @($null,'d.seitova','Dana','Seitova','Legal','Compliance Officer','employee'),
    @($null,'v.kim','Viktor','Kim','Security','SOC Analyst','employee'),
    @($null,'n.omarov','Nursultan','Omarov','Operations','Logistics Coordinator','employee'),
    @($null,'f.askarova','Farida','Askarova','HR','Recruiter','employee'),
    @($null,'i.zhaksylykov','Ilyas','Zhaksylykov','IT','Software Engineer','employee'),
    @($null,'j.ospanova','Zhanar','Ospanova','Finance','Finance Controller','employee'),
    @($null,'q.bolatov','Kuanish','Bolatov','Security','GRC Specialist','employee'),
    @($null,'s.romanenko','Sofia','Romanenko','Sales','Sales Analyst','employee')
)
# Existing service accounts keep their current SPNs and security posture.
$services = @(
    @('ir-svc-backup','svc_backup','Backup Service'),
    @('ir-svc-sync','svc_exchange','Exchange Sync Service'),
    @('ir-svc-monitor','svc_monitoring','Monitoring Service'),
    @('ir-svc-report','svc_sql','SQL Reporting Service'),
    @('ir-svc-deploy','svc_iis','IIS Deployment Service'),
    @('ir-svc-batch','svc_1c','1C Batch Service'),
    @('ir-svc-web','svc_web','Web Application Service')
)
function Assert-LabUser($user) {
    if (-not $user -or $user.DistinguishedName -notlike "*,$labOu") {
        throw "Account missing or outside lab OU: $($user.SamAccountName)"
    }
}
# Preflight every name before the first write. Never adopt a domain account.
$rows = @($people) + @($services)
$targets = @($rows | ForEach-Object { $_[1] })
if (@($targets | Select-Object -Unique).Count -ne $targets.Count) { throw 'Duplicate target names' }
$current = @{}
foreach ($row in $rows) {
    $oldName = $row[0]; $newName = $row[1]
    $old = if ($oldName) { Get-ADUser -LDAPFilter "(sAMAccountName=$oldName)" } else { $null }
    $new = Get-ADUser -LDAPFilter "(sAMAccountName=$newName)"
    if ($old) { Assert-LabUser $old }
    if ($new) { Assert-LabUser $new }
    if ($old -and $new -and $old.SID.Value -ne $new.SID.Value) {
        throw "Both legacy and target accounts exist: $oldName / $newName"
    }
    if ($oldName -and -not $old -and -not $new) { throw "Missing source and target: $oldName / $newName" }
    $current[$newName] = if ($new) { $new } else { $old }
}
$expected = @($targets) + @('ir-ldap-reader','ir-event-reader')
$legacy = @($rows | ForEach-Object { $_[0] })
$unexpected = @(Get-ADUser -SearchBase $labOu -Filter * | Where-Object {
    $_.SamAccountName -notin $expected -and $_.SamAccountName -notin $legacy
})
if ($unexpected.Count) { throw "Unexpected lab account(s): $($unexpected.SamAccountName -join ', ')" }
function New-RandomPassword {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ConvertTo-SecureString (([Convert]::ToBase64String($bytes)) + 'aA1!') -AsPlainText -Force
}
foreach ($row in $people) {
    $oldName,$newName,$given,$surname,$department,$title,$kind = $row
    $display = if ($kind -eq 'admin') { "Admin - $given $surname" } else { "$given $surname" }
    $description = if ($kind -eq 'admin') { "Separate administrative identity; $department" } else { "$department employee; $title" }
    $user = $current[$newName]
    if (-not $user) {
        New-ADUser -Name $display -DisplayName $display -GivenName $given -Surname $surname `
            -SamAccountName $newName -UserPrincipalName "$newName@infraradar.test" `
            -Department $department -Title $title -Company $company -Description $description `
            -Path $labOu -AccountPassword (New-RandomPassword) -Enabled $true
        continue
    }
    Set-ADUser -Identity $user.DistinguishedName -SamAccountName $newName `
        -UserPrincipalName "$newName@infraradar.test" -DisplayName $display `
        -GivenName $given -Surname $surname -Department $department -Title $title `
        -Company $company -Description $description
    if ($user.Name -ne $display) { Rename-ADObject -Identity $user.DistinguishedName -NewName $display }
}
foreach ($row in $services) {
    $oldName,$newName,$display = $row
    $user = $current[$newName]
    Set-ADUser -Identity $user.DistinguishedName -SamAccountName $newName `
        -UserPrincipalName "$newName@infraradar.test" -DisplayName $display `
        -Department 'IT' -Title $display -Company $company `
        -Description "Non-interactive lab service identity; $display"
    if ($user.Name -ne $display) { Rename-ADObject -Identity $user.DistinguishedName -NewName $display }
}
[pscustomobject]@{
    Domain = 'infraradar.test'
    LabOU = $labOu
    Employees = $people.Count
    Services = $services.Count
    TechnicalReaders = 2
    TotalLabUsers = @(Get-ADUser -SearchBase $labOu -Filter *).Count
} | ConvertTo-Json -Compress
