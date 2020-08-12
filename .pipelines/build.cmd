cd %~dp0..\src\Windows\dll

REM Enable cmake context and build binaries for signing
if "%VCToolsVersion%" EQU "" call "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat"

powershell -ExecutionPolicy Unrestricted -Command %~dp0..\src\Windows\dll\build.ps1 -BuildType Release -SkipRestore
 