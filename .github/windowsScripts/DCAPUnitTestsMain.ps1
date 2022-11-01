Param(
    [ValidateSet("Debug", "Release")]
    [string]$BuildType = "Debug"
)

$command = "`"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat`" x64  && "
$command += "cd C:\AzureDCAP\src\Windows\UnitTests  && "
$command += "C:\dcapBuild\nuget.exe restore UnitTests.vcxproj -PackagesDirectory packages && "
$command += "MSBuild.exe UnitTests.vcxproj /p:Configuration=$BuildType;Platform=x64 && "
$command += "xcopy /y /c C:\AzureDCAP\src\Windows\UnitTests\x64\$BuildType\UnitTests.exe C:\AzureDCAP\src\Windows\dll\x64\$BuildType && "
$command += "cd C:\AzureDCAP\src\Windows\dll\x64\$BuildType && "
$command += "UnitTests.exe  && "
$command += "echo `"DCAP_Build_Step_Successfully_Completed`""

cmd.exe /c $command