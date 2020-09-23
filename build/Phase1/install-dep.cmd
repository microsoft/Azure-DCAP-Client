@if "%echo%"=="" @echo off

nuget restore "%~dp0..\..\src\Windows\dcap_provider.sln" -PackagesDirectory "%~dp0..\..\src\Windows\Packages"

REM Invoke the Powershell packaging script.
cd %~dp0\..\..\src\Windows
powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -Command "%~dp0..\..\src\Windows\get-prereqs.ps1"
