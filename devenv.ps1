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
        Add-DVHyperVGroupToCurrentUser
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All     
    }
    else {
        Exit 0
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

    $group = Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_).name -eq "$env:COMPUTERNAME\$env:USERNAME" }
    $filter = $group | Select-String -Pattern 'Hyper' | Out-String

    return ( $filter.Trim() -ne "")
}

function Add-DVHyperVGroupToCurrentUser {
    if ((Get-DVisCurrentUserMemberOfHyperVGroup) -ne $true) {
        $hyperVGroupName = Get-DVHyperVLocalGroupName
        Add-LocalGroupMember -Group "$hyperVGroupName" -Member $env:USERNAME
    }
}

function Test-DVAdministrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function Initialize-DVFolders {
    New-Item -Path "$root" -Name ".devenv" -ItemType "directory" -Force
    New-Item -Path "$fullPath" -Name "bin\packer" -ItemType "directory" -Force
    New-Item -Path "$fullPath" -Name "vm\template" -ItemType "directory" -Force
    New-Item -Path "$fullPath" -Name "vm\base" -ItemType "directory" -Force
    New-Item -Path "$fullPath" -Name "temp" -ItemType "directory" -Force
}

function Get-DVPacker {
    $PackerRootUrl = 'https://releases.hashicorp.com/packer/'
    $Html = Invoke-RestMethod $PackerRootUrl
    $Pattern = '<a href="/packer/(?<version>.*)/">'
    $Html -match $Pattern
    $PackerUrl = $PackerRootUrl + $Matches.version + '/packer_' + $Matches.version + '_windows_amd64.zip'

    $destination = $fullPath + "\temp\packer.zip"
    Start-BitsTransfer -Source $PackerUrl -Destination $destination

    $destinationPath = $fullPath + "\bin\packer"
    Expand-Archive -Path $destination -DestinationPath $destinationPath
    Remove-Item -Path $destination -Force
}


$root = $env:USERPROFILE
$fullPath = $root + "\.devenv"

if ((Get-DVisHyperVAvailable) -ne $true) {
    if ((Test-DVAdministrator) -eq $true) {
        Enable-DVHyperV   
    }

    Write-Output 'This script needs to run as administrator to enable Hyper-V features'
    Exit 0
}

Initialize-DVFolders
Get-DVPacker

