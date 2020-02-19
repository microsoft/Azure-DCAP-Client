# Build from Visual Studio
1. Install Visual Studio 2017
1. Open `src/Windows/dcap_provider.sln`
1. Save solution and Build in Debug X64 Configuration Mode
1. Switch Configuration Mode to Release X64 mode and then Build

> The installer may not load. Please ignore this error or follow the instructions below to install the WIX toolset

# Build from Powershell
```powershell
cd src\Windows
.\get-prereqs.ps1
.\dll\build.ps1 -BuildType Debug
```
> If you get an error like the script cannot be loaded because the execution of scripts is disabled on this system, run `Set-ExecutionPolicy bypass` and accept the changes.

# Build the Installer
To build the installer Visual Studio 2017 and the WIX toolset are required.
1. Downlad the WIX Toolset from https://wixtoolset.org/releases/ and install the recommended Toolset
1. Install the Wix Toolset Visual Studio 2017 Extension. From Visual Studio select Tools->Extensions and Updates and search for "Wix Toolset Visual Studio 2017 Extension"
1. Reload the project or re-open `src/Windows/dcap_provider.sln` 


# Packaging
Run `nuget pack` in this directory. If you need to bump the version number
or any other info, update the *.nuspec file.
