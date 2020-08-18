# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
.SYNOPSIS
  This script downloads the prerequisites and builds the project using MSBuild.
  Release type is passed as an argument and can be either Debug or Release.
.PARAMETER BuildType
  The build to be performed
.EXAMPLE
  build.ps1 -BuildType Debug
#>

Param(
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug",

    [switch]$SkipRestore = $false
)


function Set-VCVariables {
    Param(
        [string]$Version="15.0",
        [string]$Platform="amd64"
    )
    if($Version -eq "15.0") {
        $vcPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\"
    } else {
        $vcPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio $Version\VC\"
    }
    if($Version -eq "BuildTools") {
        $vcPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\2017\Enterprise\VC\"
    }
    $vcVars = cmd.exe /c "`"${vcPath}\vcvarsall.bat`" $Platform & set"
    if($LASTEXITCODE -ne 0) { throw "Failed to get all VC variables" }
    $vcVars | Foreach-Object {
        if ($_ -match "=") {
            $v = $_.split("=")
            Set-Item -Force -Path "ENV:\$($v[0])" -Value "$($v[1])"
        }
    }
}

Push-Location "$PSScriptRoot"
Write-Output 'Setting Visual Studio environment variables'
Set-VCVariables -Version 'BuildTools'
if (-not($SkipRestore)) {
    Write-Output 'Restore packages with nuget'
    if(-not(Test-Path .\nuget.exe)) {
        Write-Output 'Nuget not found! Downloading...'
        Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile .\nuget.exe
    }
    .\nuget.exe restore dcap_provider.vcxproj -PackagesDirectory packages
}
Write-Output ('Running build {0}' -f $BuildType)
MSBuild.exe ..\dcap_provider.sln /p:Configuration=$BuildType /p:Platform=x64
Pop-Location
