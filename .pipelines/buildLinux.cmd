sudo apt-get purge az-dcap-client -y
sudo apt-get update
sudo apt-get install sudo libcurl4-openssl-dev wget -y
cd %~dp0/../src/Linux
-buildpackage -us -uc
dpkg -i %~dp0/../src/az-dcap-client_*_amd64.deb
sudo apt-get update
sudo apt-get install -y open-enclave
. /opt/openenclave/share/openenclave/openenclaverc
cp -r /opt/openenclave/share/openenclave/samples/ ~/samples
for DIR in \$(find ~/samples/* -maxdepth 0 -type d); do
    cd \$DIR
    make build
    make run
done