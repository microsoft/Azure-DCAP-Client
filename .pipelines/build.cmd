
# nuget install \packages.config -ExcludeVersion -Outputdirectory C:\Downloads\prereqs\nuget

cd %~dp0\..\src\Windows\dll

# REM Enable cmake context and build binaries for signing
vcvars64.bat && msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0\..\src\Windows\dcap_provider.sln"