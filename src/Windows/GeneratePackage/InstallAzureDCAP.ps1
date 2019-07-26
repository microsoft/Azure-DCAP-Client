param (
    [Parameter(Mandatory=$true)][string]$localPath
)

if (-not (Test-Path -Path $localPath))
{
    Write-Host "[ERROR]: $localPath does not exist, please provide a valid path"
}
else
{
    Copy-Item "..\dll\dcap_quoteprov.dll" -Destination $localPath
    
    $newPath = $env:Path + ";$localPath"

    Set-ItemProperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path -Value $NewPath
}
