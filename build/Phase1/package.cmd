@echo off

REM Packaging script that generates a Nuget

cd %~dp0..\..\src\Windows

REM Create the nuget package and bail if it fails to construct it
nuget pack ".\GeneratePackage\Azure.DCAP.Windows.nuspec" -Symbols -SymbolPackageFormat snupkg -OutputDirectory .\Out\packages

SET NuGetPackageRoot=