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
    New-Item -Path "$fullPath" -Name "vm\template\http" -ItemType "directory" -Force | Out-Null
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

    $templateHttpPath = $fullPath + "\vm\template\http"
    $outputVm = $fullPath + "\vm\base"
    $userAddPath = $fullPath + "\vm\template\useradd.sh"
    $provisionPath = $fullPath + "\vm\template\provision.sh"
    $packerTemplate = @"
source "hyperv-iso" "base_box" {
  boot_command       = ["root<enter><wait>", "ifconfig eth0 up && udhcpc -i eth0<enter><wait10>", "wget http://{{ .HTTPIP }}:{{ .HTTPPort }}/answers<enter><wait>", "setup-alpine -f answers<enter><wait5>", "alpine<enter><wait>", "alpine<enter><wait>", "<wait10><wait10><wait10>", "y<enter>", "<wait10><wait10><wait10>", "<wait10><wait10><wait10>", "rc-service sshd stop<enter>", "mount /dev/sda3 /mnt<enter>", "echo 'PermitRootLogin yes' >> /mnt/etc/ssh/sshd_config<enter>", "umount /mnt<enter>", "eject -s /dev/cdrom<enter>", "reboot<enter>", "<wait10><wait10><wait10>", "root<enter><wait>", "alpine<enter><wait>", "apk add hvtools<enter><wait>", "rc-update add hv_fcopy_daemon default<enter><wait>", "rc-update add hv_kvp_daemon default<enter><wait>", "rc-update add hv_vss_daemon default<enter><wait>", "reboot<enter>"]
  boot_wait          = "10s"
  communicator       = "ssh"
  disk_size          = "512"
  enable_secure_boot = false
  generation         = 1
  http_directory     = "$templateHttpPath"
  http_port_max      = "8080"
  http_port_min      = "8080"
  iso_checksum       = "92c80e151143da155fb99611ed8f0f3672fba4de228a85eb5f53bcb261bf4b0a"
  iso_url            = "http://dl-cdn.alpinelinux.org/alpine/v3.6/releases/x86_64/alpine-virt-3.6.2-x86_64.iso"
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

  provisioner "file" {
    destination = "/tmp/useradd.sh"
    source      = "$userAddPath"
  }

  provisioner "shell" {
    script = "$provisionPath"
  }

}
"@
    $outFile = $fullPath + "\vm\template\vm.pkr.hcl"
    $pattern = '[\\]'
    $packerTemplate = $packerTemplate -replace $pattern, '\\'
    $packerTemplate | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile

    $htmlAnswer = @"
KEYMAPOPTS="us us"
HOSTNAMEOPTS="-n alpine36"
INTERFACESOPTS="auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
    hostname alpine36
"
DNSOPTS="-d local -n 8.8.8.8 8.8.4.4"
TIMEZONEOPTS="-z UTC"
PROXYOPTS="none"
APKREPOSOPTS="http://dl-cdn.alpinelinux.org/alpine/v3.6/main"
SSHDOPTS="-c openssh"
NTPOPTS="-c openntpd"
DISKOPTS="-s 0 -m sys /dev/sda"
"@
    $outFile = $fullPath + "\vm\template\http\answers"
    $htmlAnswer | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile

    $addUserSh = @"
#!/bin/sh

/usr/sbin/useradd $*

# if success...
if [ `$? == 0 ]; then
        # was the passwd set in the command?
        passwd_set=
        for i in "$@"; do
                if [ `$i == "-p" -o `$i == "--password" ]; then
                        passwd_set=0
                fi
        done
        # if the passwd was set, don't mess with it
        # if no passwd was set, replace the default "!" with "*"
        # (still invalid password, but the account is not locked for ssh)
        if [ `$passwd_set ]; then
                echo "useradd: password was set, doing nothing"
        else
                echo "useradd: force default password"
                for login; do true; done
                usermod -p "*" `$login
        fi
fi
"@

    $outFile = $fullPath + "\vm\template\useradd.sh"
    $addUserSh | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile

    $provisionSh = @"
# Community package required for shadow
echo "http://dl-cdn.alpinelinux.org/alpine/v3.6/community" >> /etc/apk/repositories

apk update && apk upgrade

# Pre-reqs for WALinuxAgent
apk add openssl sudo bash shadow parted iptables sfdisk
apk add python py-setuptools

# Install WALinuxAgent
wget https://github.com/Azure/WALinuxAgent/archive/v2.2.19.tar.gz && \
tar xvzf v2.2.19.tar.gz && \
cd WALinuxAgent-2.2.19 && \
python setup.py install && \
cd .. && \
rm -rf WALinuxAgent-2.2.19 v2.2.19.tar.gz

# Update boot params
sed -i 's/^default_kernel_opts="[^"]*/\0 console=ttyS0 earlyprintk=ttyS0 rootdelay=300/' /etc/update-extlinux.conf
update-extlinux

# sshd configuration
sed -i 's/^#ClientAliveInterval 0/ClientAliveInterval 180/' /etc/ssh/sshd_config

# Start waagent at boot
cat > /etc/init.d/waagent <<EOF
#!/sbin/openrc-run  
                                                               
export PATH=/usr/local/sbin:`$PATH

start() {                                                                          
        ebegin "Starting waagent"                                                  
        start-stop-daemon --start --exec /usr/sbin/waagent --name waagent -- -start
        eend `$? "Failed to start waagent"                                          
}
EOF

chmod +x /etc/init.d/waagent
rc-update add waagent default

# Workaround for default password
# Basically, useradd on Alpine locks the account by default if no password
# was given, and the user can't login, even via ssh public keys. The useradd.sh script
# changes the default password to a non-valid but non-locking string.
# The useradd.sh script is installed in /usr/local/sbin, which takes precedence
# by default over /usr/sbin where the real useradd command lives.
mkdir -p /usr/local/sbin
mv /tmp/useradd.sh /usr/local/sbin/useradd
chmod +x /usr/local/sbin/useradd
"@

    $outFile = $fullPath + "\vm\template\provision.sh"
    $provisionSh | Out-File $outFile -Encoding ascii
    ConvertTo-UnixtextFile -fileName $outFile
}

function Start-DVPackerBuild {
    $packer = $fullPath + "\bin\packer\packer.exe"
    $workDir = $fullPath + "\vm\base"
    $vmtemplate = $fullPath + "\vm\template\vm.pkr.hcl"
    Start-Process -FilePath $packer -ArgumentList "build", "-force", $vmtemplate  -Wait -NoNewWindow -WorkingDirectory $workDir 
    #-WindowStyle hidden
    #-Verb RunAs
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
