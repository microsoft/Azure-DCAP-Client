#!/usr/bin/env bash
set -e

if [[ -z "${SUBSCRIPTION_ID:-}" ]]; then echo "Must specify SUBSCRIPTION_ID"; exit 1; fi
if [[ -z "${TENANT:-}" ]]; then echo "Must specify TENANT"; exit 1; fi

if [[ -z "${SERVICE_PRINCIPAL_ID:-}" ]]; then echo "Must specify SERVICE_PRINCIPAL_ID"; exit 1; fi
if [[ -z "${SERVICE_PRINCIPAL_PASSWORD:-}" ]]; then echo "Must specify SERVICE_PRINCIPAL_PASSWORD"; exit 1; fi

az login --service-principal -u $SERVICE_PRINCIPAL_ID -p $SERVICE_PRINCIPAL_PASSWORD --tenant $TENANT
az account set --subscription $SUBSCRIPTION_ID

wget -q https://oejenkinsciartifacts.blob.core.windows.net/oe-engine/latest/bin/oe-engine
chmod 755 oe-engine

wget -q https://raw.githubusercontent.com/Microsoft/oe-engine/master/test/oe-ub1604.json
sed -i "s_\"keyData\": \"\"_\"keyData\": \"$oeengine_public_key\"_g" oe-ub1604.json

if [ "$OS" = "Linux" ]; then  
  ./oe-engine generate --api-model oe-ub1604.json
else
  echo "Unsupported OS $OS"
  exit 1
fi

RGNAME="oe-pck-test-$OS-$LOCATION-$BUILD_NUMBER"
az group create --name $RGNAME --location $LOCATION
trap 'az group delete --name $RGNAME --yes --no-wait' EXIT
az group deployment create -n acclnx -g $RGNAME --template-file _output/azuredeploy.json --parameters _output/azuredeploy.parameters.json

DEPLOY_IP="`az vm show -d --name acc-ub1604 --resource-group $RGNAME | jq '.publicIps' | sed 's/"//g'`"

COMMAND_TO_RUN="
set -x
set -e
sudo apt-get -y install libcurl4-openssl-dev
git clone https://github.com/Microsoft/Azure-DCAP-Client.git 
cd Azure-DCAP-Client/src/Linux
./configure
make
cd ~
wget https://oejenkins.blob.core.windows.net/publicdrops/oesdk/1/open-enclave-0.4.1-Linux.deb
sudo dpkg -i open-enclave-0.4.1-Linux.deb
cp -R /opt/openenclave/share/openenclave/samples/ ~/
. /opt/openenclave/share/openenclave/openenclaverc
cd samples/remote_attestation
make
export LD_LIBRARY_PATH=~/Azure-DCAP-Client/src/Linux/
if [ -n '$AZ_BASE_CERT_URL' ]; then
  export AZDCAP_BASE_CERT_URL='$AZ_BASE_CERT_URL'
fi
export OE_LOG_LEVEL=VERBOSE
make run"

echo "$COMMAND_TO_RUN" > test-script.sh
chmod +x test-script.sh

chmod 600 $oeengine_private_key
mkdir -p ~/.ssh/
ssh-keyscan -H $DEPLOY_IP > ~/.ssh/known_hosts

scp -i $oeengine_private_key test-script.sh azureuser@$DEPLOY_IP:~

set +e
echo "Connecting to new vanilla ACC system at $DEPLOY_IP..."
ssh -tt -i $oeengine_private_key -o ServerAliveInterval=30 -o ServerAliveCountMax=2 -o ConnectionAttempts=2 azureuser@$DEPLOY_IP "./test-script.sh 2>&1"
exit $?
