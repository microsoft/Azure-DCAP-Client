#
# This script will generate a Nuget package as defined by the nuspec file.
#

# Get the location of all the appropriate directories
$binDir = Get-Item $env:ENCLAVE_BUILD_OUTPUT_DIR
$packageDir =  Get-Item $env:ENCLAVE_BUILD_PACKAGE_OUTPUT_DIR
$scriptDir =  Get-Item $env:ScriptDir
$specName = "AttestationSgxEnclave.nuspec"
$buildType = "Dev"

# Determine build type if we are running in the build pipeline
if ($env:CDP_BUILD_TYPE)
{
    $buildType = $env:CDP_BUILD_TYPE
}

# Get the nuspec file
$spec = Get-Item "$scriptDir\$specName"

# Determine version string from the build pipeline, else use hardcoded value
if ($env:CDP_FILE_VERSION_NUMERIC)
{
    $version =  $env:CDP_FILE_VERSION_NUMERIC
}
else
{
    $version = "0.0.0.9999"
}

# If this is not a Official build mark the package as such
if ($buildType -notmatch "Official")
{
    $version = $version + "-" + $buildType
}

# Create a string for the nuspec properties
$prop = "Version=`"$version`";BinRoot=`"$binDir`""

# Dump some information for diagnostics
Write-Host "Version: $version"
Write-Host "Script: $scriptDir"
Write-Host "Bin: $binDir"
Write-Host "Package: $packageDir"
Write-Host "Properties: $prop"

# Create the nuget package and bail if it fails to construct it
nuget pack "$spec" -Properties "$prop" -OutputDirectory "$packageDir" -verbosity detailed

if ($LastExitCode -ne 0)
{
    return $LastExitCode
}
