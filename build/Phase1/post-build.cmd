@echo off

echo After Build End
echo Out: %~dp0\..\..\src\AttestationServices\Instance\Out
dir %~dp0\..\..\src\AttestationServices\Instance\Out
dir /s %~dp0\..\..\src\AttestationServices\Instance\Out\AttestationSgxEnclave
