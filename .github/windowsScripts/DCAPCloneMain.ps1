Param(
    [Parameter(Mandatory=$true)][string]$repo,
    [Parameter(Mandatory=$true)][string]$branch
)

# Delete old folder (quietly), then clone, then echo on success
cmd.exe /c "rmdir /s /q C:\AzureDCAP"

# Build a proper cmd.exe command line
$command = "git clone -b $branch $repo ""C:\AzureDCAP"" && echo ""DCAP_Build_Step_Successfully_Completed"""

cmd.exe /c $command