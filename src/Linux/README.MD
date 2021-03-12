# Build

## Prerequisites
This library requires libcurl built with OpenSSL support and package config.

* `sudo apt-get install libssl-dev`
* `sudo apt install libcurl4-openssl-dev`
* `sudo apt-get install pkg-config`

Install Google Test
```
sudo apt-get update -y
sudo apt-get install -y libgtest-dev
sudo apt-get install -y cmake
cd /usr/src/gtest
sudo cmake CMakeLists.txt
sudo make

# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.a /usr/lib
```

Additionally, if you used the standard git clone command to pull down the repo without initializing the submodule, you may have to run the following to initialize the submodule:

* `git submodule update –recursive –init`


## Quick Start
```
./configure
make
sudo make install
```

## Run Google Test
```
cmake CMakeLists.txt
make
./dcap_provider_utests

If cmake needs to update, please run:
sudo apt remove cmake
sudo apt-get install python-pip
pip install cmake --upgrade
```

## Step-by-Step
1. `./configure`
    * This pulls down prerequisites from other projects, finds correct local
      paths, and creates `Makefile`
1. `make`
    * Builds `libdcap_quoteprov.so`, the provider library.
1. `sudo make install` (optional)
    * Installs the library to `/usr/local/lib` and header to `/usr/local/include`.
1. `make DEBUG=1` (optional)
    * Builds the library with the -g flag

# Packaging

## Debian
To build a Debian package, you'll need an Ubuntu/Debian system with the
build-essential package (`sudo apt install build-essential`) and dh-virtualenv 
(`sudo apt-get install debhelper dh-virtualenv`) installed. 

1. Update `src/Linux/debian/changelog` with a description of the changes which
   require a new package to be published.
1. Copy over the files in `src` to a new directory called
   `az-dcap-client-{VERSION}`, where {VERSION} the latest version number
   specified in Linux/debian/changelog.
1. Run the following commands:
    * `tar czf az-dcap-client_{VERSION}.orig.tar.gz az-dcap-client-{VERSION}`
    * `cd az-dcap-client-{VERSION}/Linux && dpkg-buildpackage -us -uc`

The output deb file is suitable for installation on any amd64 Ubuntu system.

## Troubleshooting

1. You're seeing cryptic errors such as ": No such file or directory":
    * This can happen if the files are copied from a Windows host to a
      Linux host. Run dos2unix on all files to be sure none of them have Windows
      line-endings.
