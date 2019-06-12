# Build
1. Install Visual Studio 2017
1. Open `src/Windows/dcap_provider.vcxproj`
1. Save solution and Build in Debug X64 Configuration Mode
1. Switch Configuration Mode to Release X64 mode and then Build

# Build from Powershell
```powershell
cd src\Windows
.\get-prereqs.ps1
.\build.ps1 -BuildType Debug
```
> If you get an error like the script cannot be loaded because the execution of scripts is disabled on this system, run `Set-ExecutionPolicy bypass` and accept the changes.


# Packaging
Run `nuget pack` in this directory. If you need to bump the version number
or any other info, update the *.nuspec file.

Note: Your output package includes:
  libcurl.dll
  libeay32.dll
  libssh2.dll
  ssleay32.dll
  zlib.dll
These DLLs have the following external dependencies:
https://www.microsoft.com/en-us/download/details.aspx?id=30679#
https://www.microsoft.com/en-us/download/details.aspx?id=52685
