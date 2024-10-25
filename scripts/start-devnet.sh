#!/bin/bash

ENV=$1

if [ -z "$ENV" ]; then
  echo "Usage: start-devnet.sh <ENV>"
  exit 1
fi

echo "Starting the devnet on $ENV..."

# the environment needs to match the image tags in the kurtosis config file
sed "s/\$TAG/$ENV/g" ./scripts/kurtosis_config.template.yaml > ./scripts/kurtosis_config.yaml

# spin up the kurtosis devnet
kurtosis run --enclave bolt-devnet github.com/chainbound/ethereum-package@bolt --args-file ./scripts/kurtosis_config.yaml

echo "Devnet started!"
