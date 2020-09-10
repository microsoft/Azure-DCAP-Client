@echo off

REM Configure Visual Studio
if not defined DevEnvDir (
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -winsdk=10.0.16299.0
)

REM Directory
SET dir=%~dp0..

REM GoogleTestAdapter
FOR /F "tokens=*" %%i IN ('powershell -Command "& {Write-Host ((Get-ChildItem -Path (Join-Path '%DevEnvDir%' Extensions) -Recurse | Where-Object { $_.Name -eq 'GoogleTestAdapter.TestAdapter.dll' } | Select-Object -First 1).DirectoryName)}"') do @SET gta=%%i

REM Test
vstest.console.exe^
  %dir%\build\x64\test\unit\Release\UnitTests.exe^
  /TestAdapterPath:"%gta%"^
  /Platform:x64^
  /logger:trx;LogFileName=Release.trx