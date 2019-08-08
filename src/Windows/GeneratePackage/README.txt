# Azure DCAP for Windows
# Description
Azure DCAP is a plugin library component to the Intel DCAP for interfacing with
the Azure PCK Caching Service.

# Nuget Package Layout
- dll    - dcap_quoteprovider.dll : Azure DCAP for Windows DLL
- script - InstallAzureDCAP.ps1   : Script to install Azure DCAP

# Azure DCAP Installation
Navigate to script\ and run powershell script in elevated mode .\InstallAzureDCAP.ps1 <provide-local-path-here>. The script copies the Azure DCAP dll to the provided location and updates the PATH variable.
Be sure to restart all dependent services so they are referring to the updated PATH environment variable.