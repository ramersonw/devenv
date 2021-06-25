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

function Enable-DVOpenSSH {
    $ssh = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.C*'
    if ($ssh.State -ne "Installed") {
        Add-WindowsCapability -Online -Name $ssh.Name
    }
}
function Enable-DVHyperV {
    Write-Output 'This script will enable Hyper-V features'
    $answer = Read-Host -Prompt 'Your system may reboot. Continue? (Y / N)'

    if ($answer.ToUpper() -eq "Y") {
        Add-DVHyperVGroupToCurrentUser
        Enable-DVOpenSSH
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
    New-Item -Path "$fullPath" -Name "vm\projects" -ItemType "directory" -Force | Out-Null
    New-Item -Path "$fullPath" -Name "vm\sshkey" -ItemType "directory" -Force | Out-Null
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

function Add-DVSshKey {
    $pathFile = $fullPath + "\vm\sshkey\id_rsa"
    ssh-keygen.exe -f $pathFile -q -N """"
}

function Get-DVPackerTemplate {
    $outputVm = $fullPath + "\vm\base"
    $sshKeyPath = $fullPath + "\vm\sshkey\id_rsa.pub"
    $provisionPath = $fullPath + "\vm\template\provision.sh"
    $tempPath = $fullPath + "\temp"

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
  boot_wait             = "10s"
  communicator          = "ssh"
  disk_size             = 40960
  disk_block_size       = 1
  enable_secure_boot    = false
  enable_dynamic_memory = true
  generation            = 1
  cpus                  = 2
  iso_checksum          = "d568c6c71bb1eee0f65cdf40088daf57032e24f1e3bd2cf8a813f80d2e9e4eab"
  iso_url               = "https://dl-cdn.alpinelinux.org/alpine/v3.14/releases/x86_64/alpine-virt-3.14.0-x86_64.iso"
  output_directory      = "$outputVm"
  shutdown_command      = "poweroff"
  skip_compaction       = false
  ssh_password          = "alpine"
  ssh_username          = "root"
  switch_name           = "Default Switch"
  headless              = false
  temp_path             = "$tempPath"
}

build {
  sources = ["source.hyperv-iso.base_box"]

  provisioner "file" {
    destination = "/tmp/id_rsa.pub"
    source      = "$sshKeyPath"
  }
  
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
mkdir -p /root/.ssh
mv /tmp/id_rsa.pub /root/.ssh/authorized_keys
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
    Add-DVSshKey
    $packer = $fullPath + "\bin\packer\packer.exe"
    $workDir = $fullPath + "\vm\base"
    $vmtemplate = $fullPath + "\vm\template\vm.pkr.hcl"
    Start-Process -FilePath $packer -ArgumentList "build", "-force", $vmtemplate  -Wait -NoNewWindow -WorkingDirectory $workDir 
}

function Get-DVVmName {
    $vmName = Get-Location
    $pathHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::New([System.Text.Encoding]::ASCII.GetBytes($vmName.Path)))-Algorithm MD5)
    return (Split-Path $vmName.Path -Leaf) + $pathHash.Hash    
}

function Import-DVVM {
    $vmName = Get-DVVmName

    $registeredVm = get-vm $vmName -ErrorAction SilentlyContinue
    if ($null -ne $registeredVm.Name) {
        return
    }

    $vmcxPath = $fullPath + '\vm\base\Virtual Machines\*.vmcx'
    $vmcx = Get-ChildItem "$vmcxPath"
    if ([int]$vmcx.length -eq 0) {
        Write-Output "There's no base vm to import"
        Exit 0        
    }

    $pathVm = $fullPath + '\vm\base\Virtual Machines\' + $vmcx.Name
    $vmData = $fullPath + '\vm\projects\' + $vmName
    $vmHd = $fullPath + "\vm\projects\" + $vmName + "\Virtual Hard Disks"
    Import-VM -Path "$pathVm" -Copy -GenerateNewId -VirtualMachinePath "$vmData" -VhdDestinationPath "$vmHd" -SnapshotFilePath "$vmData" -SmartPagingFilePath "$vmData"
    Rename-VM "packer-base_box" -NewName $vmName
}

function Start-DVVm {
    Start-VM -Name (Get-DVVmName)
    Start-Sleep -s 10
}

function Get-DVVmIp {
    $VM = Get-VM -Name (Get-DVVmName)
    
    $Adapter = ($VM | Get-VMNetworkAdapter)
    return $Adapter.IPAddresses[0] 
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
Import-DVVM
Start-DVVm
Get-DVVmIp
Write-Output "iniciou"
