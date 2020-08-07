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

REM Install packages listed in packages.config
nuget install %ScriptDir%\packages.config -ExcludeVersion -Outputdirectory %PackageDir% %NugetSource%



cd %ENCLAVE_BUILD_SOURCE_ROOT%\Windows\dll

powershell .\get-prereqs.ps1

if %errorlevel% NEQ 0 exit /b %errorlevel%
exit /b 0

