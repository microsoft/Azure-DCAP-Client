setlocal

rem Initialize Build environment. Set Global includes as a part of
rem this, needed for packaging.
call "%~dp0\..\..\init.cmd" norestore


REM Package up the MDS Runner binaries.
echo Calling: "msbuild /p:Platform=x64 /p:Configuration=Release -target:ZipPackage %~dp0\..\..\src\MdsRunners\Package\Package.proj"
msbuild /p:Platform=x64 /p:Configuration=Release -target:ZipPackage %~dp0\..\..\src\MdsRunners\Package\Package.proj
if %errorlevel% neq 0 exit /b %errorlevel%

REM Package up the MAA Geneva Monitoring binaries.
echo Calling: "msbuild /p:Platform=x64 /p:Configuration=Release  %~dp0\..\src\AttestationServices\Monitoring\Monitoring.proj"
msbuild /p:Platform=x64 /p:Configuration=Release  %~dp0\..\..\src\AttestationServices\Monitoring\Monitoring.proj
if %errorlevel% neq 0 exit /b %errorlevel%

REM Package up the Deployment binaries.
echo Calling: "msbuild /p:Platform=x64 /p:Configuration=Release  %~dp0\..\..\src\AttestationServices\Deployments\deployments.proj"
msbuild -t:RobocopyFiles,PatchEV2TemplateVersion -p:Platform=x64  -p:Configuration=Release %~dp0\..\..\src\AttestationServices\Deployments\deployments.proj
if %errorlevel% neq 0 exit /b %errorlevel%

REM Package the attestation servicefabric package (When run during primary build, it creates unsigned packages).
echo Calling: "msbuild /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=%~dp0\..\..\src\ /p:CdpxPostSigning=true  /p:NoBuild=true %~dp0\..\..\src\AttestationServices\ServiceFabricApplication\AttestationApplication.sfproj"
msbuild /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=%~dp0\..\..\src\ /p:CdpxPostSigning=true  /p:NoBuild=true %~dp0\..\..\src\AttestationServices\ServiceFabricApplication\AttestationApplication.sfproj
if %errorlevel% neq 0 exit /b %errorlevel%

REM Package the SgxPckCache Service binaries
echo Calling "msbuild /t:ZipPackage /p:CdpxPostSigning=true /p:Configuration=Release /p:Platform=x64 %~dp0\..\..\src\SgxPckCertSupport\SgxPckCertService\SgxPckCertService.csproj"
msbuild /t:ZipPackage /p:CdpxPostSigning=true /p:NoBuild=true /p:Configuration=Release /p:Platform=x64 %~dp0\..\..\src\SgxPckCertSupport\SgxPckCertService\SgxPckCertService.csproj
if %errorlevel% neq 0 exit /b %errorlevel%

REM call :DumpEnclaveImage "%~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\AttestationSgxEnclaveLoader\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\AttestationRp\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\AttestationTenant\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\EnclaveHost\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\AttestationRpPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\AttestationTenantPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\EnclaveHostPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\UnitTests\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\Wrapper\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\out\Release\WrapperTests\AttestationSgxEnclave.signed"
exit /b 0

:DumpEnclaveImage
echo Dump enclave %1
%~dp0\..\..\src\Tools\InPath\oesign dump --enclave-image %1
exit /b 0
