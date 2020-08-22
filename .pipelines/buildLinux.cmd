#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

dpkg -i $DIR/../src/az-dcap-client_*_amd64.deb

cd $DIR/../src
mkdir GoogleTest 
cp CMakeLists.txt ./GoogleTest/.
cmake CMakeLists.txt
make
