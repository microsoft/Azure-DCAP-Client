@if "%echo%"=="" @echo off

REM Install Nuget dependencies and other pre-requisites.

REM Run the Environment variables setup script
call %~dp0setenv.cmd

REM Get the current script directory
SET ScriptDir=%~dp0.

REM Set the package directory
SET PackageDir=%ENCLAVE_BUILD_NUGET_DIR%

REM On Devbox LOCAL_NUGET_DIR can be set to a local container directory that contains the packages
if NOT "%ENCLAVE_BUILD_NUGET_SOURCE_OVERRIDE%"=="" (
    SET NugetSource=-Source "%ENCLAVE_BUILD_NUGET_SOURCE_OVERRIDE%"
)

nuget restore "%~dp0..\..\src\Windows\dcap_provider.sln" -PackagesDirectory %PackageDir%

REM Install packages listed in packages.config
REM nuget install %~dp0..\..\src\Windows\dll\packages.config -ExcludeVersion -Outputdirectory %PackageDir% %NugetSource%

REM Invoke the Powershell packaging script. This script needs to be run from the src\Windows\dll directory.
cd %~dp0\..\..\src\Windows
powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -Command "%~dp0..\..\src\Windows\get-prereqs.ps1"
