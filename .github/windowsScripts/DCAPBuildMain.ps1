Param(
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug"
)

$command = "`"C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvars64.bat`" x64  && "
$command += "cd D:\AzureDcap\Azure-DCAP-Client\src\Windows && "
$command += "D:\AzureDcap\Azure-DCAP-Client\src\Windows\dll\nuget.exe restore D:\AzureDcap\Azure-DCAP-Client\src\Windows\dcap_provider.sln -PackagesDirectory packages && "
$command += "powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive `"D:\AzureDcap\Azure-DCAP-Client\src\Windows\get-prereqs.ps1`" && "
$command += "cd D:\AzureDcap\Azure-DCAP-Client\src\Windows\dll && "
$command += "D:\AzureDcap\Azure-DCAP-Client\src\Windows\dll\nuget.exe restore D:\AzureDcap\Azure-DCAP-Client\src\Windows\dll\dcap_provider.vcxproj -PackagesDirectory packages && "
$command += "MSBuild.exe D:\AzureDcap\Azure-DCAP-Client\src\Windows\dll\dcap_provider.vcxproj /p:Configuration=$BuildType;Platform=x64 && "
$command += "echo `"DCAP_Build_Step_Successfully_Completed`""

cmd.exe /c $command
