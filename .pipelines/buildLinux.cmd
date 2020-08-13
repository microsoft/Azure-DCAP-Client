#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

cd $DIR/../src/Linux/

dpkg-buildpackage -us -uc
dpkg -i $DIR/../../src/az-dcap-client_*_amd64.deb