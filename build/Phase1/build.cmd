@if "%echo%"=="" @echo off

REM Main build script to build the enclave

REM Run the Environment variables setup script
call %~dp0setenv.cmd

REM Get the current script directory
SET ScriptDir=%~dp0.

REM Get the build compiler type
if /I "%~1"=="MSVC" (
    SET CMakeBuildParams=-DENCLAVE_BUILD_USE_MSVC=ON
)

REM Get the build type
if /I "%~2"=="Release" (
    SET CMakeBuildParams=%CMakeBuildParams% -DCMAKE_BUILD_TYPE=Release
) else (
    SET CMakeBuildParams=%CMakeBuildParams% -DCMAKE_BUILD_TYPE=Debug
)

REM Set the package directory
SET NugetPackageDir=%ENCLAVE_BUILD_NUGET_DIR%

REM Launch VS Build environment
if "%VCINSTALLDIR%"=="" call vcvars64.bat
if NOT "%echo%"=="" echo on

REM Create a symbolic link to Window SDK directory since the
REM default path contains spaces and Clang fails to compile
mklink /D %ENCLAVE_BUILD_WINSDK_DIR% "%WindowsSdkDir%"

REM Create a symbolic link to VCTools directory since the
REM default path contains spaces and Clang fails to compile
mklink /D %ENCLAVE_BUILD_VCTOOLS_DIR% "%VCToolsInstallDir%"

REM Create the output directory
mkdir %ENCLAVE_BUILD_OUTPUT_DIR%

REM Create the package output directory
mkdir %ENCLAVE_BUILD_PACKAGE_OUTPUT_DIR%

REM Set the Enclave Source directory relative to current script path
SET EnclaveSourceDir=%ENCLAVE_BUILD_SOURCE_ROOT%

REM OpenEnclave_DIR that is required by OE CMake scripts
SET OpenEnclave_DIR=%NugetPackageDir%\open-enclave\openenclave\lib\openenclave\cmake

REM Change to output directory
cd %ENCLAVE_BUILD_OUTPUT_DIR%

REM Generate the Ninja build scripts using CMake
cmake %EnclaveSourceDir% -G Ninja -DNUGET_PACKAGE_PATH=%NugetPackageDir% %CMakeBuildParams%

REM Run Ninja build
ninja -j 1 -v