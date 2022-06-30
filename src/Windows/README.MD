# Build from Visual Studio
1. Install Visual Studio 2017
1. Use powershell to run `.\get-prereqs.ps1`
1. Open `src/Windows/dcap_provider.sln`
1. Save solution and Build in Debug X64 Configuration Mode
1. Switch Configuration Mode to Release X64 mode and then Build

> The installer may not load. Please ignore this error or follow the instructions below to install the WIX toolset

# Build from Powershell
1. Launch the Developer Command Prompt for VS 2017
1. Start powershell 
1. Run the build script:
```powershell
cd src\Windows
.\get-prereqs.ps1
.\dll\build.ps1 -BuildType <Release/Debug>
```
> If you get an error like the script cannot be loaded because the execution of scripts is disabled on this system, run `Set-ExecutionPolicy bypass` and accept the changes.

# Build the Installer
To build the installer Visual Studio 2017 or 2019 and the WIX toolset are required.
1. Downlad the WIX Toolset from https://wixtoolset.org/releases/ and install the recommended Toolset
1. Install the Wix Toolset Visual Studio Extension. From Visual Studio search for "Wix Toolset Visual Studio Extension"
1. Reload the project or re-open `src/Windows/dcap_provider.sln` 

# Packaging
1. Run the build script in Release mode
1. Run `nuget pack` in the GeneratePackage directory. If you need to bump the version number or any other info, update the *.nuspec file.
> If you get an error like "The element 'metadata' in namespace..." Please use a newer version of nuget.exe
