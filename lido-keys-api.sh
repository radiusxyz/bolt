#!/usr/bin/env bash

set -eo pipefail

private_key="$PRIVATE_KEY"

# Check if PRIVATE_KEY is set
if [[ -z "$private_key" ]]; then
    echo "Error: PRIVATE_KEY env is not set."
    exit 1
fi

# validator pubkey to query
pubkey="0xb5dd6bc1669c903d23734a5a6cac8917955980648e1e79121482e200315972287740ac62001709454b2dc2c806920260"

# 1. call lido keys API to fetch the validator information
res=$(curl -s http://34.88.187.80:30303/v1/preconfs/lido-bolt/validators/$pubkey | jq)

operator_rpc=$(echo $res | jq -r '.rpcUrl')

# check that operator_rpc is not empty
if [[ -z "$operator_rpc" ]]; then
    echo "Error: Operator RPC URL is not found."
    exit 1
fi

# 2. use bolt cli to send a preconfirmation to that operator
bolt send --private-key $private_key --max-fee 4 --priority-fee 3 --override-bolt-sidecar-url $operator_rpc
