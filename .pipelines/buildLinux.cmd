#!/bin/bash

cd %~dp0/../src/Linux/

sudo apt-get install libssl-dev
sudo apt install libcurl4-openssl-dev
sudo apt-get install pkg-config

git submodule update –recursive –init

./configure

make

sudo make install