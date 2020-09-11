cd %~dp0..\..\src\Windows

# Create the nuget package and bail if it fails to construct it
nuget pack .\GeneratePackage\Azure.DCAP.Windows.nuspec -Symbols -SymbolPackageFormat snupkg