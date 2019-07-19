# Build
1. Install Visual Studio 2017
1. Open `src/Windows/dcap_provider.sln`
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
