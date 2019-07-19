# Azure DCAP for Windows
# Description
Azure DCAP is a plugin library component to the Intel DCAP for interfacing with
the Azure PCK Caching Service.

# VCRuntime Dependencies
Please ensure that you have both the VC++ v110 and v140 runtimes installed
on your system.

VC++ Runtime v110: https://www.microsoft.com/en-us/download/details.aspx?id=30679
VC++ Runtime v140: https://www.microsoft.com/en-us/download/details.aspx?id=53840

# Nuget Package Layout
- dll    - dcap_quoteprovider.dll : Azure DCAP for Windows DLL
         - libcurl.dll            : List of dependent DLLs
         - libeay32.dll           
         - libssh2.dll
         - ssleay32.dll
         - zlib.dll
- crl    - curl-ca-bundle.crt     : Global Root CA
- script - InstallAzureDCAP.ps1   : Script to install Azure DCAP

# Azure DCAP Installation
1. Navigate to script\
2. Run powershell script in elevated mode .\InstallAzureDCAP.ps1 <provide-local-path-here>
3. Ensure that you are installing next to the Intel DCAP to ensure plugin linkage at runtime.

