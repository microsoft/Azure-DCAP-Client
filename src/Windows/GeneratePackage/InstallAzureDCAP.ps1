param (
    [Parameter(Mandatory=$true)][string]$localPath
)

if (-not (Test-Path -Path $localPath))
{
    Write-Host "$localPath does not exist, creating it."
    New-Item -ItemType Directory -Force -Path $localPath
}
else
{
    Write-Host "Copying dcap_quoteprov.dll into $localPath"
    Copy-Item "..\dll\dcap_quoteprov.dll" -Destination $localPath
    
    $newPath = $env:Path + ";$localPath"

    Write-Host "Updating the system PATH variable with $localPath"
    Set-ItemProperty -path 'hklm:\system\currentcontrolset\control\session manager\environment' -Name Path -Value $NewPath
}
