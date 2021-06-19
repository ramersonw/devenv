function Get-DVisHyperVAvailable {
    $result = $false
    try {
        Get-VM | Out-Null
        $result = $true
    } catch {
    }

    return $result
}

$isHyperVAvailable = Get-DVisHyperVAvailable


if ($isHyperVAvailable -ne $true) {
    Write-Output 'O Hyper-V não está habilitado no seu sistema.'
    Write-Output 'Execute o script (como administrador) usando o parâmetro "--enable-Hyper-V" para habilitar o Hyper-V'
    Write-Output 'O sistema será reiniciado em seguida.'
    #Get-WindowsOptionalFeature -Online -FeatureName *hyper*

    #$Server = Read-Host -Prompt 'Input your server  name'
    #$User = Read-Host -Prompt 'Input the user name'
    #$Date = Get-Date
    #Write-Host "You input server '$Servers' and '$User' on '$Date'"
} else {
    Write-Output "outro"
}