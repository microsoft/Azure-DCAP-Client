@echo off

echo After Build End
echo Out: %~dp0\..\..\src\Windows\Out
dir %~dp0\..\..\src\Windows\Out
dir /s %~dp0\..\..\src\Windows\Out\AzureDCAPClient
