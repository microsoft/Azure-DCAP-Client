
# nuget install \packages.config -ExcludeVersion -Outputdirectory C:\Downloads\prereqs\nuget

cd %~dp0\..\src\Windows\dll

powershell -ExecutionPolicy Bypass -Command "{& [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;  \'Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile .\\nuget.exe\';}"

# REM Enable cmake context and build binaries for signing
vcvars64.bat && msbuild -p:Configuration=Release /p:Platform=x64 "%~dp0\..\src\Windows\dcap_provider.sln"