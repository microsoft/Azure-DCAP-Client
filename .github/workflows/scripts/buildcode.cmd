#! /bin/bash


# Get the directory where this script resides
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd $DIR/../../src/Linux/

make clean
./configure
make