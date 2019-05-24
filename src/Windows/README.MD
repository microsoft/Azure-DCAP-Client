# Build
1. Install Visual Studio 2017
1. Open `src/Windows/dcap_provider.vcxproj`
1. Build

# Packaging
Run `nuget pack` in this directory. If you need to bump the version number
or any other info, update the *.nuspec file.

Note: You the output package includes:
  libcurl.dll
  libeay32.dll
  libssh2.dll
  ssleay32.dll
  zlib.dll
These DLLs have the following external dependencies:
https://www.microsoft.com/en-us/download/details.aspx?id=30679#
https://www.microsoft.com/en-us/download/details.aspx?id=52685
