cd %~dp0..\src

REM Enable cmake context and build binaries for signing
vcvars64.bat && msbuild -p:Configuration=Release /p:Platform=x64 ".\Windows\dcap_provider.sln"