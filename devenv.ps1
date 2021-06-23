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
	
    if ($filter.Trim() -eq "") {
        $group = Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_).name -eq "$env:USERDOMAIN\$env:USERNAME" }
        $filter = $group | Select-String -Pattern 'Hyper' | Out-String        
    }

    return ( $filter.Trim() -ne "")
}

function Add-DVHyperVGroupToCurrentUser {
    if ((Get-DVisCurrentUserMemberOfHyperVGroup)) {
        $hyperVGroupName = Get-DVHyperVLocalGroupName
        Add-LocalGroupMember -Group "$hyperVGroupName" -Member $env:USERNAME
    }
}

function Test-DVAdministrator {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function Initialize-DVFolders {
    New-Item -Path "$root" -Name ".devenv" -ItemType "directory" -Force | Out-Null
    New-Item -Path "$fullPath" -Name "bin\packer" -ItemType "directory" -Force | Out-Null
    New-Item -Path "$fullPath" -Name "vm\template" -ItemType "directory" -Force | Out-Null
    New-Item -Path "$fullPath" -Name "vm\base" -ItemType "directory" -Force | Out-Null
    New-Item -Path "$fullPath" -Name "temp" -ItemType "directory" -Force | Out-Null
}

function Get-DVPacker {
    $packerPath = $fullPath + "\bin\packer\packer.exe"
    $packerExists = Test-Path -Path $packerPath -PathType Leaf
    if ($packerExists) {
        return
    }
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

function ConvertTo-UnixtextFile {

    param (
        $fileName
    )

    Get-ChildItem $fileName | ForEach-Object {
        $contents = [IO.File]::ReadAllText($_) -replace "`r`n?", "`n"
        $utf8 = New-Object System.Text.UTF8Encoding $false
        [IO.File]::WriteAllText($_, $contents, $utf8)
    }
}

function Get-DVPackerTemplate {

    $outputVm = $fullPath + "\vm\base"
    $provisionPath = $fullPath + "\vm\template\provision.sh"

    $packerTemplate = @"
source "hyperv-iso" "base_box" {
  boot_command       = [
    "root<enter><wait>", 
	"ifconfig eth0 up && udhcpc -i eth0<enter><wait5>", 
	"echo 'KEYMAPOPTS=*us us*' > answers<enter>",
	"echo 'HOSTNAMEOPTS=*-n alpine*' >> answers<enter>",
	"echo 'INTERFACESOPTS=*auto lo' >> answers<enter>",
	"echo 'iface lo inet loopback' >> answers<enter>",
	"echo '' >> answers<enter>",
	"echo 'auto eth0' >> answers<enter>",
	"echo 'iface eth0 inet dhcp' >> answers<enter>",
	"echo '    hostname alpine' >> answers<enter>",
	"echo '*' >> answers<enter>",
	"echo 'DNSOPTS=*-d local -n 8.8.8.8 8.8.4.4*' >> answers<enter>",
	"echo 'TIMEZONEOPTS=*-z UTC*' >> answers<enter>",
	"echo 'PROXYOPTS=*none*' >> answers<enter>",
	"echo 'APKREPOSOPTS=*http://dl-cdn.alpinelinux.org/alpine/v3.14/main*' >> answers<enter>",
	"echo 'SSHDOPTS=*-c openssh*' >> answers<enter>",
	"echo 'NTPOPTS=*-c none*' >> answers<enter>",
	"echo 'DISKOPTS=*-s 0 -m sys /dev/sda*' >> answers<enter>",
	"setup-alpine -f answers<enter><wait5>", 
	"alpine<enter><wait>", 
	"alpine<enter><wait>", 
	"<wait5>", 
	"y<enter>", 
	"<wait10><wait10><wait10>", 
	"<wait10>", 
	"rc-service sshd stop<enter>", 
	"mount /dev/sda2 /mnt<enter><wait>", 
	"echo 'PermitRootLogin yes' >> /mnt/etc/ssh/sshd_config<enter>", 
	"umount /mnt<enter>", 
	"eject -s /dev/cdrom<enter>", 
	"reboot<enter>", 
	"<wait10><wait10>", 
	"root<enter><wait>", 
	"alpine<enter><wait>", 
	"apk add hvtools<enter><wait>", 
	"rc-update add hv_fcopy_daemon default<enter><wait>", 
	"rc-update add hv_kvp_daemon default<enter><wait>", 
	"rc-update add hv_vss_daemon default<enter><wait>", 
	"reboot<enter>"
  ]
  boot_wait          = "10s"
  communicator       = "ssh"
  disk_size          = "512"
  enable_secure_boot = false
  generation         = 1
  iso_checksum       = "d568c6c71bb1eee0f65cdf40088daf57032e24f1e3bd2cf8a813f80d2e9e4eab"
  iso_url            = "https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-virt-3.14.0-x86_64.iso"
  output_directory   = "$outputVm"
  shutdown_command   = "poweroff"
  skip_compaction    = "true"
  ssh_password       = "alpine"
  ssh_username       = "root"
  switch_name        = "Default Switch"
  headless           = false
}

build {
  sources = ["source.hyperv-iso.base_box"]

  provisioner "shell" {
    script = "$provisionPath"
  }

}
"@
    $outFile = $fullPath + "\vm\template\vm.pkr.hcl"
    $pattern = '[\\]'
    $packerTemplate = $packerTemplate -replace $pattern, '\\'
    $pattern = '[*]'
    $packerTemplate = $packerTemplate -replace $pattern, '\"'	
    $packerTemplate | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile

    $provisionSh = @"
# Community package required for shadow
echo "http://dl-cdn.alpinelinux.org/alpine/v3.14/community" >> /etc/apk/repositories

apk update && apk upgrade
"@

    $outFile = $fullPath + "\vm\template\provision.sh"
    $provisionSh | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile
}

function Start-DVPackerBuild {
    $vmVhdPath = $fullPath + "\vm\base\Virtual Hard Disks\packer-base_box.vhdx"
    $vhdExists = Test-Path -Path "$vmVhdPath" -PathType Leaf
    if ($vhdExists) {
        return
    }
    $packer = $fullPath + "\bin\packer\packer.exe"
    $workDir = $fullPath + "\vm\base"
    $vmtemplate = $fullPath + "\vm\template\vm.pkr.hcl"
    Start-Process -FilePath $packer -ArgumentList "build", "-force", $vmtemplate  -Wait -NoNewWindow -WorkingDirectory $workDir 
}


$root = $env:USERPROFILE
$fullPath = $root + "\.devenv"

if (-not(Get-DVisHyperVAvailable)) {
    if ((Test-DVAdministrator)) {
        Enable-DVHyperV   
    }

    Write-Output 'This script needs to run as administrator to enable Hyper-V features'
    Exit 0
}

Initialize-DVFolders
Get-DVPacker
Get-DVPackerTemplate
Start-DVPackerBuild
Write-Output "iniciou"
