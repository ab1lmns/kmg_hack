# Read-only effective user-rights snapshot for the lab DC and lab service users.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Import-Module ActiveDirectory
$domain = Get-ADDomain
if ($domain.DNSRoot -ne 'infraradar.test') { throw 'Unexpected domain' }
$labOu = 'OU=InfraRadarLab,DC=infraradar,DC=test'
$file = Join-Path $env:TEMP ('ir-rights-' + [guid]::NewGuid().ToString() + '.inf')
try {
    secedit /export /mergedpolicy /areas user_rights /cfg $file /quiet | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $file)) { throw 'secedit export failed' }
    $keys = @('SeInteractiveLogonRight','SeDenyInteractiveLogonRight',
              'SeRemoteInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight')
    $rights = @{}
    foreach ($key in $keys) { $rights[$key] = @() }
    foreach ($line in Get-Content $file) {
        if ($line -match '^\s*(Se\w+LogonRight)\s*=\s*(.*)$') {
            foreach ($key in $keys) {
                if ($matches[1] -ieq $key) {
                    $rights[$key] = @($matches[2].Split(',') | ForEach-Object {
                        $_.Trim().TrimStart('*')
                    } | Where-Object { $_ })
                }
            }
        }
    }
    $tokens = @{}
    Get-ADUser -SearchBase $labOu -Filter * -Properties servicePrincipalName |
        Where-Object { $_.SamAccountName -like 'ir-svc-*' -or $_.ServicePrincipalName } |
        ForEach-Object {
            $principal = Get-ADObject -Identity $_.DistinguishedName -Properties tokenGroups
            $tokens[$_.SamAccountName.ToLowerInvariant()] = @(
                @($principal.tokenGroups | ForEach-Object { $_.Value }) +
                @('S-1-1-0','S-1-5-11')
            )
        }
    [pscustomobject]@{
        target_host = $env:COMPUTERNAME
        source_policy = 'secedit /export /mergedpolicy /areas user_rights'
        collected_at = (Get-Date).ToUniversalTime().ToString('o')
        rights = $rights
        token_sids = $tokens
    } | ConvertTo-Json -Depth 6 -Compress
} finally {
    Remove-Item $file -ErrorAction SilentlyContinue
}
