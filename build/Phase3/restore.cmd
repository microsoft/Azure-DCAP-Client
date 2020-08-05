if "%_ECHO%"=="" @echo off
echo "Restoring Dependencies"
setlocal enableextensions 

rem Initialize VS tools if they're not alreay initialized.
call "%~dp0\..\..\init.cmd" norestore

call :RestoreNugetPackages
if %errorlevel% neq 0 exit /b %errorlevel%

call :RestorePreviousPhases
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b


:RestoreNugetPackages
REM Restore C# package references and packages.
call :msbuildrestorewithretry "%~dp0\..\..\src\Microsoft Azure Attestation.sln"
if %errorlevel% neq 0 exit /b %errorlevel%

REM Restore C++ packages.
call :nugetrestorewithretry "%~dp0\..\..\src\Microsoft Azure Attestation.sln"
if %errorlevel% neq 0 exit /b %errorlevel%

REM Restore Packaging packages.
call :nugetrestorewithretry "%~dp0\..\..\src\MdsRunners\Package\Package.proj" %~dp0\..\..\src\packages
if %errorlevel% neq 0 exit /b %errorlevel%

call :nugetrestorewithretry "%~dp0\..\..\src\AttestationServices\Monitoring\Monitoring.proj" %~dp0\..\..\src\packages
if %errorlevel% neq 0 exit /b %errorlevel%

call :nugetrestorewithretry "%~dp0\..\..\src\AttestationServices\UpdatePackage\UpdatePackage.proj" %~dp0\..\..\src\packages
if %errorlevel% neq 0 exit /b %errorlevel%

call :nugetrestorewithretry "%~dp0\..\..\src\AttestationServices\Deployments\Deployments.proj" %~dp0\..\..\src\packages
if %errorlevel% neq 0 exit /b %errorlevel%

call :nugetrestorewithretry "%~dp0\..\..\src\AttestationServices\ServiceFabricApplication\AttestationApplication.sfproj" %~dp0\..\..\src\packages
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b


:RestorePreviousPhases

REM Restore collateral from previous build phases.

if "%CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%" EQU "" exit /b 0

REM dir %CDP_TEMP_PRIOR_DROP_FOLDER_CONTAINER_PATH%
echo "Build Sources Directory: %BUILD_SOURCESDIRECTORY%"
dir %BUILD_SOURCESDIRECTORY%
echo "Artifacts"
dir %BUILD_SOURCESDIRECTORY%\artifacts
echo "Artifacts\Phase1"
dir %BUILD_SOURCESDIRECTORY%\artifacts\Phase_1
echo "Artifacts\Phase2"
dir %BUILD_SOURCESDIRECTORY%\artifacts\Phase_2

set PHASE_1_DROP_LOCATION=%BUILD_SOURCESDIRECTORY%\artifacts\Phase_1\build
set PHASE_2_DROP_LOCATION=%BUILD_SOURCESDIRECTORY%\artifacts\Phase_2\build
echo Phase 1 Drop: %PHASE_1_DROP_LOCATION%
echo Phase 2 Drop: %PHASE_2_DROP_LOCATION%

echo Phase 1:
dir /s %PHASE_1_DROP_LOCATION%
echo Phase 2:
dir /s %PHASE_2_DROP_LOCATION%

REM Copy artifacts from the previous phases to their appropriate
REM location in the build hierarchy.
robocopy %PHASE_1_DROP_LOCATION%\AttestationSgxEnclave\Host %~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader *.*
echo Error Level from Phase 1 copy: %errorlevel%
if %errorlevel% geq 8 exit /b %errorlevel%

echo Copy %PHASE_2_DROP_LOCATION%\AttestationSgxEnclave to %~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader
dir  %PHASE_2_DROP_LOCATION%\AttestationSgxEnclave
dir %~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader
robocopy %PHASE_2_DROP_LOCATION%\AttestationSgxEnclave %~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader *.*
echo Error Level from Phase 2 copy: %errorlevel%
if %errorlevel% geq 8 exit /b %errorlevel%

call :DumpEnclaveImage "%~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader\AttestationSgxEnclave.signed"

exit /b 0

:DumpEnclaveImage
echo Dump enclave %1
%~dp0\..\..\src\Tools\InPath\oesign dump --enclave-image %1
exit /b 0


REM Actually run the Nuget Restore command. Retry each get three times 
:NugetRestoreWithRetry
echo Restoring packages from %1 to directory %2.
call :NugetRestore %1 %2
if %errorlevel% equ 0 exit /b %errorlevel%
call :NugetRestore %1 %2
if %errorlevel% equ 0 exit /b %errorlevel%
call :NugetRestore %1 %2
exit /b %errorlevel%

:NugetRestore
if "%2" EQU "" nuget restore %1
if not "%2" EQU "" nuget restore %1 -PackagesDirectory %2
exit /b %errorlevel%



:MsBuildRestoreWithRetry
msbuild -t:restore %1
if %errorlevel% equ 0 exit /b %errorlevel%
msbuild -t:restore %1
if %errorlevel% equ 0 exit /b %errorlevel%
msbuild -t:restore %1
exit /b %errorlevel%
