@echo off

REM Packaging script that generates a Nuget

powershell -ExecutionPolicy Unrestricted -Command "package.ps1"

SET NuGetPackageRoot=