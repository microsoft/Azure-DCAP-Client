$command = "rmdir /s /q C:\AzureDCAP  && "
$command += "echo `"Old_DCAP_Build_Step_Successfully_Cleaned`""

cmd.exe /c $command