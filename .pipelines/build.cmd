
nuget install %~dp0\packages.config -ExcludeVersion -Outputdirectory C:\Downloads\prereqs\nuget

REM Enable cmake context and build binaries for signing
vcvars64.bat && msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0\..\src\Windows\dcap_provider.sln"