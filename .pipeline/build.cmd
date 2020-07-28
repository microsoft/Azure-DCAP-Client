cd source

REM Create and cd into build directory
mkdir build 
cd build 

REM Enable cmake context and build binaries for signing
vcvars64.bat && cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\Downloads\prereqs\nuget -DCPACK_GENERATOR=NuGet -DCMAKE_BUILD_TYPE=Release -DBUILD_ENCLAVES=ON -DLVI_MITIGATION=ControlFlow -DHAS_QUOTE_PROVIDER=ON && ninja -j 1 -v