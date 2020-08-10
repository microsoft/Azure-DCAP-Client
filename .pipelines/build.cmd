cd %~dp0..\src\Windows

powershell -ExecutionPolicy Unrestricted -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command ".\dll\build.ps1 -BuildType Release"