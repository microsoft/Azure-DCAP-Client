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
    Copy-Item "..\dll\libcurl.dll" -Destination $localPath
    Copy-Item "..\dll\libeay32.dll" -Destination $localPath
    Copy-Item "..\dll\libssh2.dll" -Destination $localPath
    Copy-Item "..\dll\ssleay32.dll" -Destination $localPath
    Copy-Item "..\dll\zlib.dll" -Destination $localPath
    Copy-Item "..\crt\curl-ca-bundle.crt" -Destination $localPath
    
    $env:Path += ";" + $localPath

    [Environment]::SetEnvironmentVariable
     ("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

    if ((-not (Test-Path -Path "$env:windir\System32\msvcp140.dll")) -or
        (-not (Test-Path -Path "$env:windir\System32\msvcr110.dll")) -or
        (-not (Test-Path -Path "$env:windir\System32\vcruntime140.dll")))
    {
        Write-Host "[WARNING]: Not all dependent v110 and v140 runtimes seem
        to be present on system. Please ensure that you have those installed."
    }
}
