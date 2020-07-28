REM Create and cd into build directory
cd source/build

REM Enable cmake context and package binaries for signing
vcvars64.bat && cpack -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY && cpack