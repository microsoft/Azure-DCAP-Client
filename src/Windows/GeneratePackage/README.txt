# Azure DCAP for Windows
# Description
Azure DCAP is a plugin library component to the Intel DCAP for interfacing with
the Azure PCK Caching Service.

# Nuget Package Layout
- dll    - dcap_quoteprovider.dll : Azure DCAP for Windows DLL
- script - InstallAzureDCAP.ps1   : Script to install Azure DCAP

# Azure DCAP Installation
1. Navigate to script\
2. Run powershell script in elevated mode .\InstallAzureDCAP.ps1 <provide-local-path-here>
3. Ensure that you are installing next to the Intel DCAP to ensure plugin linkage at runtime.

