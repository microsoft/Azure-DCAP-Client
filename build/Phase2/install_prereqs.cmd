#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

apt-get install libssl-dev
apt install libcurl4-openssl-dev
apt-get install pkg-config

add-apt-repository ppa:team-xbmc/ppa -y
apt-get update
apt-get install nlohmann-json3-dev

apt install build-essential

apt-get install -y debhelper dh-virtualenv

# install GoogleTest
apt-get update -y
apt-get install -y libgtest-dev
apt-get install -y cmake
cd /usr/src/gtest
cmake CMakeLists.txt
make
# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
cp *.a /usr/lib

cd $DIR/../../src/Linux/

./configure

make

make install

dpkg-buildpackage -us -uc



