#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

apt-get install libssl-dev
apt install libcurl4-openssl-dev
apt-get install pkg-config

apt install build-essential

apt-get install debhelper dh-virtualenv

