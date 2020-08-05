echo "Building Microsoft Azure Attestation Service"

rem Initialize Build environment. Set Global includes as a part of
rem this.
call "%~dp0\..\..\init.cmd" norestore


call :BuildMaaBuildArtifacts
if %errorlevel% neq 0 exit /b %errorlevel%

exit /b 0

:BuildMaaBuildArtifacts
msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0\..\..\src\Microsoft Azure Attestation.sln"
if %errorlevel% neq 0 exit /b %errorlevel%

REM call :DumpEnclaveImage "%~dp0\..\..\src\AttestationServices\Instance\AttestationSgxEnclaveLoader\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\AttestationSgxEnclaveLoader\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\AttestationRp\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\AttestationTenant\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\EnclaveHost\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\AttestationRpPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\AttestationTenantPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\ServiceGroupRoot\AttestationApp\PackageTmp\EnclaveHostPkg\Code\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\UnitTests\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\Wrapper\AttestationSgxEnclave.signed"
REM call :DumpEnclaveImage "%~dp0\..\..\src\out\Release\WrapperTests\AttestationSgxEnclave.signed"
exit /b 0

:DumpEnclaveImage
echo Dump enclave %1
%~dp0\..\..\src\Tools\InPath\oesign dump --enclave-image %1
exit /b 0
