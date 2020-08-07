
# nuget install \packages.config -ExcludeVersion -Outputdirectory C:\Downloads\prereqs\nuget

# REM Enable cmake context and build binaries for signing
vcvars64.bat && powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "%ENCLAVE_BUILD_SOURCE_ROOT%\Windows\get-prereqs.ps1" && msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0\..\src\Windows\dcap_provider.sln"