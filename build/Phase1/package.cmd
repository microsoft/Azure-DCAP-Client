@echo off

REM Packaging script that generates a Nuget

REM Run the Environment variables setup script
call %~dp0setenv.cmd

REM Get the current script directory
SET ScriptDir=%~dp0.

REM Invoke the Powershell packaging script
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "%ScriptDir%\package.ps1"