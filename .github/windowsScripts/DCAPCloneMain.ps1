Param(
    [Parameter(Mandatory=$true)][string]$repo,
    [Parameter(Mandatory=$true)][string]$branch
)

$command = "git clone -b $branch $repo C:/AzureDCAP  && "
$command += "echo `"DCAP_Build_Step_Successfully_Completed`""

cmd.exe /c "rmdir /s /q C:\AzureDCAP"
cmd.exe /c $command