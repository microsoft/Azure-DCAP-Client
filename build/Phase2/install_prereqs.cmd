#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

apt-get install libssl-dev
apt-get update -y
apt install libcurl4-openssl-dev -y
apt-get install pkg-config -y

add-apt-repository ppa:team-xbmc/ppa -y
apt-get update -y
apt-get install nlohmann-json3-dev

apt install build-essential -y

#apt-get install -y debhelper dh-virtualenv

# install GoogleTest
apt-get update -y
apt-get install -y libgtest-dev
apt-get install -y cmake
cd /usr/src/gtest
cmake CMakeLists.txt
make
cd lib
# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
cp *.a /usr/lib

cd $DIR/../../src/Linux/

make clean
./configure
make
make install

#dpkg-buildpackage -us -uc



