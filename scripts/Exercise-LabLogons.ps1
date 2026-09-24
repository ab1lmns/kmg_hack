param(
    [switch]$Apply,
    [string[]]$Account = @(
        'a.bekov', 'a.orynbek', 'd.seitova', 'e.ivanov',
        'f.askarova', 'i.zhaksylykov', 'j.ospanova', 'k.zhumabek',
        'l.serikova', 'n.omarov', 'p.kuandykova', 'q.bolatov'
    )
)

# Generate real recent logons for ordinary lab users without editing AD time attributes.
# Passwords exist only in process memory and are never printed or persisted.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
if ((Get-ADDomain).DNSRoot -ne 'infraradar.test' -or $env:COMPUTERNAME -ne 'INFRARADAR-DC01') {
    throw 'Unexpected domain controller'
}
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$allowed = @(
    'a.bekov', 'a.orynbek', 'd.seitova', 'e.ivanov',
    'f.askarova', 'i.zhaksylykov', 'j.ospanova', 'k.zhumabek',
    'l.serikova', 'n.omarov', 'p.kuandykova', 'q.bolatov'
)
if (-not $Account.Count -or @($Account | Select-Object -Unique).Count -ne $Account.Count) {
    throw 'Empty or duplicate account list'
}
$users = @()
foreach ($sam in $Account) {
    if ($sam -notin $allowed) { throw "Account not approved for logon exercise: $sam" }
    $user = Get-ADUser -Identity $sam -Properties Enabled,PasswordNeverExpires,AccountExpirationDate,LastLogon
    if ($user.DistinguishedName -notlike "*,$labOu" -or -not $user.Enabled -or
        $user.PasswordNeverExpires -or $user.AccountExpirationDate) {
        throw "Account is not an ordinary active lab employee: $sam"
    }
    $users += $user
}
if (-not $Apply) {
    [pscustomobject]@{Mode='DRY_RUN';Accounts=$users.Count;LabOU=$labOu} | ConvertTo-Json -Compress
    return
}
$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
    [System.DirectoryServices.AccountManagement.ContextType]::Domain,
    'infraradar.test'
)
try {
    foreach ($user in $users) {
        $bytes = New-Object byte[] 48
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $plain = ([Convert]::ToBase64String($bytes)) + 'aA1!'
        $secure = ConvertTo-SecureString $plain -AsPlainText -Force
        Set-ADAccountPassword -Identity $user.DistinguishedName -Reset -NewPassword $secure
        if (-not $context.ValidateCredentials($user.SamAccountName, $plain)) {
            throw "Successful logon could not be verified for $($user.SamAccountName)"
        }
        $plain = $null
    }
} finally {
    $context.Dispose()
}
[pscustomobject]@{Mode='APPLIED';Accounts=$users.Count;LabOU=$labOu} | ConvertTo-Json -Compress
