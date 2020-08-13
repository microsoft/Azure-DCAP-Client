#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

apt-get install libssl-dev
apt install libcurl4-openssl-dev
apt-get install pkg-config

apt install build-essential

apt-get install -y debhelper dh-virtualenv

cd $DIR/../../src/Linux/

./configure

make

make install

dpkg-buildpackage -us -uc
dpkg -i $DIR/../../src/az-dcap-client_*_amd64.deb

