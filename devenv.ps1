$ErrorActionPreference = "Stop"

function Get-DVisHyperVAvailable {

    $result = $false
    try {
        Get-VM | Out-Null
        $result = $true
    }
    catch {
    }

    return $result
}
function Enable-DVHyperV {
    Write-Output 'This script will enable Hyper-V features'
    $answer = Read-Host -Prompt 'Your system may reboot. Continue? (Y / N)'

    if ($answer.ToUpper() -eq "Y") {
        
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All     
    }
}
function Get-DVHyperVLocalGroupName {
    <#
        .NOTES
            Returns an empty string if Hyper-V group was not found.
    #>

    $hyperVGroup = Get-LocalGroup | Select-String -Pattern 'Hyper' | Out-String

    return $hyperVGroup.Trim()
}

function Get-DVisCurrentUserMemberOfHyperVGroup {
    <#
        .NOTES
            Returns an empty string if current user is not member of Hyper-V group.
    #>

    $group = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }
    $filter = $group | Select-String -Pattern 'Hyper' | Out-String

    return ( $filter.Trim() -ne "")
}

function Add-DVHyperVGroupToCurrentUser {
    $hyperVGroupName = Get-DVHyperVLocalGroupName
    Add-LocalGroupMember -Group $hyperVGroupName -Member $env:USERNAME
}

function Test-DVAdministrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

if ((Get-DVisHyperVAvailable) -ne $true) {
    if ((Test-DVAdministrator) -eq $true) {
        Enable-DVHyperV   
    }

    Write-Output 'This script needs to run as administrator to enable Hyper-V features'
    Exit-PSHostProcess
}

