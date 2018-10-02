# Build

## Prerequisites
This library requires libcurl built with OpenSSL support.

* On Ubuntu/Debian: `sudo apt install libcurl-openssl-dev`

## Quick Start
```
./configure
make
make install
```

## Step-by-Step
1. `./configure`
    * This pulls down prerequisites from other projects, finds correct local
      paths, and creates `Makefile`
1. `make`
    * Builds `libdcap_quoteprov.so`, the provider library.
1. `make install` (optional)
    * Installs the library to `/usr/local/lib` and header to `/usr/local/include`.

# Packaging

## Debian
To build a Debian package, you'll need an Ubuntu/Debian system with the
build-essential package installed. (`sudo apt install build-essential`).

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
