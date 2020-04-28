param (
    [Parameter(Mandatory=$true)][string]$localPath
)


function Add-ToSystemPath
{
    Param(
        [Parameter(Mandatory=$false)]
        [string[]]$Path
    )
    if(!$Path)
    {
        return
    }
    $registryLocation = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $systemPath = (Get-ItemProperty -Path $registryLocation -Name Path).Path.Split(';')
    $currentPath = $env:PATH.Split(';')
    foreach($p in $Path)
    {
        if($p -notin $systemPath)
        {
            $systemPath += $p
        }
        if($p -notin $currentPath)
        {
            $currentPath += $p
        }
    }
    $env:PATH = $currentPath -join ';'
    $newSystemPath = $systemPath -join ';'
    Set-ItemProperty -Path $registryLocation -Name Path -Value $newSystemPath
}


if (-not (Test-Path -Path $localPath))
{
    Write-Host "$localPath does not exist, creating it."
    New-Item -ItemType Directory -Force -Path $localPath
}

Write-Host "Copying dcap_quoteprov.dll into $localPath"
Copy-Item "..\build\native\dcap_quoteprov.dll" -Destination $localPath

Write-Host "Updating the system PATH variable with $localPath"
Add-ToSystemPath -Path $localPath
