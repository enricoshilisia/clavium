<#
.SYNOPSIS
  Writes Clavium managed settings to HKLM\SOFTWARE\Policies\Clavium.
  For Intune (Devices > Scripts and remediations, run as SYSTEM, 64-bit)
  or any tool that runs PowerShell as an administrator. Edit the values
  below; remove a line to leave that setting unmanaged.
#>
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Policies\Clavium'

$settings = @{
    ServerUrl              = ''                    # e.g. 'https://vault.contoso.com' (empty = standard Clavium service)
    AllowedEmailDomains    = 'contoso.com'         # comma separated
    DisableAccountCreation = 1                     # 1 = accounts only from IT invites
    RequireSignIn          = 1                     # 1 = remind until signed in
    MaxAutoLockMinutes     = 10                    # 1..1440
}

New-Item -Path $key -Force | Out-Null
foreach ($name in $settings.Keys) {
    $value = $settings[$name]
    if ($value -is [int]) {
        New-ItemProperty -Path $key -Name $name -Value $value -PropertyType DWord -Force | Out-Null
    } elseif ([string]::IsNullOrWhiteSpace($value)) {
        Remove-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue
    } else {
        New-ItemProperty -Path $key -Name $name -Value $value -PropertyType String -Force | Out-Null
    }
}
Write-Output "Clavium settings written to $key"
