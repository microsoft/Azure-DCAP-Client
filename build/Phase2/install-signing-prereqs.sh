#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

sudo apt-get install libssl-dev
sudo apt install libcurl4-openssl-dev
sudo apt-get install pkg-config

git submodule update –recursive –init

sudo apt install build-essential

sudo apt-get install debhelper dh-virtualenv

