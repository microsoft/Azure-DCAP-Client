if "%echo%"=="" @echo off

REM Sets up environment variables used by the build scripts

REM Set the build nuget directory
SET ENCLAVE_BUILD_NUGET_DIR=C:\source\src\Windows\dll\packages

REM Set the build WinSDK directory
SET ENCLAVE_BUILD_WINSDK_DIR=C:\Downloads\prereqs\WinSdk

REM Set the build VCTools directory
SET ENCLAVE_BUILD_VCTOOLS_DIR=C:\Downloads\prereqs\VCTools

REM Set the build source root directory
SET ENCLAVE_BUILD_SOURCE_ROOT=%~dp0..\..\src

REM Set the build output directory
if "%ENCLAVE_BUILD_OUT_OVERRIDE%"=="" (
    SET ENCLAVE_BUILD_OUTPUT_DIR=%ENCLAVE_BUILD_SOURCE_ROOT%\Out
) else (
    SET ENCLAVE_BUILD_OUTPUT_DIR=%ENCLAVE_BUILD_OUT_OVERRIDE%
)

REM Set the build nuget directory
SET ENCLAVE_BUILD_PACKAGE_OUTPUT_DIR=%ENCLAVE_BUILD_OUTPUT_DIR%\Package
