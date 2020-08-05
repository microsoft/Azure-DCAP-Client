#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

cd $DIR/../src/Linux/

apt-get install libssl-dev
apt install libcurl4-openssl-dev
apt-get install pkg-config

git submodule update –recursive –init

./configure

make

make install