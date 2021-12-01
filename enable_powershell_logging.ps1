#Check Powershell version
Get-Host | Select-Object Version

#Check for Powershell v2 engine
$powershellv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
if($powershellv2.State -eq "Enabled")
{write-host "PowerShell v2 Engine Enabled" -ForegroundColor Red
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
}
#Check for Powershell v2
$powershellv2root = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2root
if($powershellv2.State -eq "Enabled")
{write-host "PowerShell v2 root Enabled" -ForegroundColor Red
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2root -NoRestart
}

#Install PowerrShell 7

#MSI version (download from github) - https://github.com/PowerShell/PowerShell/releases/
#msiexec.exe /package PowerShell-7.2.0-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1


winget search microsoft.powershell
#Winget package manager silently
winget install microsoft.powershell --silent --accept-package-agreements  --accept-source-agreements

#Enable Logging

#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2
#HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
#HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\Transcription
#HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging

#New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force

function Enable-PSScriptBlockLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ScriptBlockLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
}

Enable-PSScriptBlockLogging


function Enable-PSModuleLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ModuleLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableModuleLogging -Value "1"
}

Enable-PSModuleLogging

function Enable-PSTransactionLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\transaction'

      $PSLogDir = 'c:\pstranscriptlogs'
      New-Item -ItemType Directory -Path $PSLogDir -Force
    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableTransacting -Value "1"
    Set-ItemProperty $basePath -Name EnableInvocationHeader -Value "1"
    Set-ItemProperty $basePath -Name "OutputDirectory" -Value $PSLogDir
}

Enable-PSTransactionLogging

$acl = Get-Acl $PSLogDir

#remove inheritance
$acl.SetAccessRuleProtection($true,$true)
$acl |Set-Acl $PSLogDir

#lazy mode remove Users and authenticated users ACLs using icacls

icacls C:\pstranscriptlogs /remove users /t
icacls C:\pstranscriptlogs /remove "Authenticated Users" /t


#Enable Constrained Language Mode
# https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
# you can do this locally with a system varaible: __PSLockDownPolicy set to "4" but it affects ALL users

#Configure and Deploy Windows Defender Application Control (WDAC)
# this is done via GPO or INTUNE - for GPO this requires Enterprise Edition of Windows CLient
# see also applocker
# https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/requirements-to-use-applocker
