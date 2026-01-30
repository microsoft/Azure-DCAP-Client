Param(
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug"
)

$command = "`"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat`" x64  && "
$command += "cd C:\AzureDCAP\src\Windows && "
$command += "C:\dcapBuild\nuget.exe restore dcap_provider.sln -PackagesDirectory packages && "
$command += "powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive `"C:\AzureDCAP\src\Windows\get-prereqs.ps1`" && "
$command += "cd C:\AzureDCAP\src\Windows\dll && "
$command += "C:\dcapBuild\nuget.exe restore dcap_provider.vcxproj -PackagesDirectory packages && "
$command += "MSBuild.exe dcap_provider.vcxproj /p:Configuration=$BuildType;Platform=x64 && "
$command += "echo `"DCAP_Build_Step_Successfully_Completed`""

cmd.exe /c $command
