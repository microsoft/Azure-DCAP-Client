cd %~dp0..\src\Windows\dll

REM Enable cmake context and build binaries for signing
if "%VCToolsVersion%" EQU "" call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"

powershell -ExecutionPolicy Unrestricted -Command %~dp0..\src\Windows\dll\build.ps1 -BuildType Release -SkipRestore
 
msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0..\src\Windows\dcap_provider_tests\dcap_provider_tests.vcxproj"