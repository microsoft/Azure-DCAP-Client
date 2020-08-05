rem Initialize VS tools if they're not alreay initialized.
setlocal enabledelayedexpansion
setlocal enableextensions
if "%VCToolsVersion%" EQU "" call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"

set _MBB_VSTEST="%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Extensions\TestPlatform\vstest.console.exe"

REM Commented out UnitTests.dll and EnclaveUT.dll - these tests require internet access
REM and cannot be run in the primary build environment. Instead
REM they'll be run in CloudTest outside this script.
REM call !_MBB_VSTEST! %~dp0\..\..\out\Release\UnitTests\UnitTests.dll /Platform:x64 /logger:trx
REM call !_MBB_VSTEST! %~dp0\..\..\out\Release\EnclaveUT\EnclaveUT.dll /Platform:x64 /logger:trx
call !_MBB_VSTEST! %~dp0\..\..\out\Release\PalUT\PalUT.dll /Platform:x64 /logger:trx;LogFileName=PalUt.trx /Collect:"Code Coverage"
if %errorlevel% neq 0 exit /b %errorlevel%

call !_MBB_VSTEST! %~dp0\..\..\out\Release\WrapperTests\WrapperTests.dll /Platform:x64 /logger:trx;LogFileName=WrapperTests.trx
if %errorlevel% neq 0 exit /b %errorlevel%
