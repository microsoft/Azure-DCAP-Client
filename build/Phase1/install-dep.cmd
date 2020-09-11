@if "%echo%"=="" @echo off

nuget restore "%~dp0..\..\src\Windows\dcap_provider.sln" -PackagesDirectory "%~dp0..\..\src\Windows\Packages"

REM Install packages listed in packages.config
REM nuget install %~dp0..\..\src\Windows\dll\packages.config -ExcludeVersion -Outputdirectory %PackageDir% %NugetSource%

REM Invoke the Powershell packaging script. This script needs to be run from the src\Windows\dll directory.
cd %~dp0\..\..\src\Windows
powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -Command "%~dp0..\..\src\Windows\get-prereqs.ps1"
