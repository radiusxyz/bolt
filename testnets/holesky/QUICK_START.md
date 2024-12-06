# Holesky Validator Opt-in Quick Start Guide

> [!IMPORTANT]
> This quick guide skips the details and provides a step-by-step practical guide
> to opt-in to Bolt on the Holesky testnet.
>
> You need to have at least 1 Holesky validator node running to opt-in to Bolt.
> This includes an Execution client, a Beacon client, and a Validator client,
> and at least 1 beacon chain deposit of 32 ETH.

## 0. Pre-requisites

You will need the following dependencies on your machine:

- [Install Docker](https://docs.docker.com/get-docker/)

Additionally, you will need:

- A running Holesky validator node (at least 32 ETH deposited in the beacon chain)
  - Control of your private keys (e.g. a local keystore directory or remote Dirk instance)
- A Holesky wallet funded with a few testnet ETH

## 1. Clone the bolt repository

```bash
git clone https://github.com/chainbound/bolt && cd bolt
```

## 2. Install the bolt CLI

To install the bolt CLI, you can either use our pre-built binaries or build it from source.

### Using pre-built binaries

```bash
# download the bolt-cli installer
curl -L https://raw.githubusercontent.com/chainbound/bolt/unstable/boltup/install.sh | bash

# start a new shell to use the boltup installer
exec $SHELL

# install the bolt-cli binary for holesky
boltup --tag v0.1.0

# check for successful installation
bolt --help
```

### Building from source

You will need the following dependencies to build the bolt CLI yourself:

- [Install Rust](https://www.rust-lang.org/tools/install)
- [Install Protoc](https://grpc.io/docs/protoc-installation/)

```bash
cd bolt-cli
cargo install --force --path .

# check for successful installation
bolt --help
```

## 3. Obtain a list of your validator public keys

This CLI command will list all the public keys of your validator(s) and save them
in a `pubkeys.json` file in the current directory. It works with different key sources
depending on where your keys are stored:

<details>
<summary>If your keys are stored in a local keystore directory</summary>

- NOTE: Right now the `local-keystore` source only supports `lighthouse` style keystores
  (with `validators` and `secrets` subdirectories containing the keystores and passwords respectively).

```bash
bolt pubkeys local-keystore --path <validators_path>
```

Example file structure when using `local-keystore` source:

```bash
- validator_keys
    - validators
        - 0x1234567890...abcde
            - voting-keystore.json
        - 0xabcdef1234...567890
        - validator_definitions.yml
    - secrets
        - 0x1234567890...abcdef
        - 0xabcdef1234...567890
```

In this case you would run the command (called from the `validator_keys` directory):

```bash
bolt pubkeys local-keystore --path validators
```

</details>

<details>
<summary>If your keys are stored on a remote Dirk instance</summary>

- NOTE: You will need to have a running Dirk instance and the necessary TLS certificates to access
  the wallets inside it.

```bash
bolt pubkeys dirk --url <dirk_url> \
  --client-cert-path <client_cert_path> \
  --client-key-path <client_key_path> \
  --ca-cert-path <ca_cert_path> \
  --wallet-path <wallet_path> --passphrases <passphrase>
```

Example Dirk setup might look like this:

```bash
- dirk
    - client_1.crt
    - client_1.key
    - ca.crt
```

</details>

## 4. Register your validators in the `BoltValidators` contract

- NOTE: Before running this command, make sure you have the `pubkeys.json` file generated in the previous step.
- NOTE: You will need a new wallet to use as **operator** for the validators (`--authorized-operator` flag).
  You can generate a new keypair using [`cast wallet new`](https://book.getfoundry.sh/reference/cast/cast-wallet-new) if needed.

```bash
bolt validators register \
    --rpc-url http://localhost:8545 \
    --max-committed-gas-limit 10000000 \
    --authorized-operator <operator_address> \
    --pubkeys-path pubkeys.json \
    --admin-private-key <admin_wallet_private_key>
```

Where:

- `--rpc-url` is the URL of an Ethereum execution node (e.g. Geth) to send transactions to
- `--max-committed-gas-limit` is the maximum gas limit for the committed transactions
- `--authorized-operator` is the **address of the operator that will be authorized to sign commitments**
- `--pubkeys-path` is the path to the `pubkeys.json` file generated in the previous step
- `--admin-private-key` is the private key of the **admin account** that will register the validators
  (as such, it needs to be a wallet with some testnet ETH to pay for gas)

> [!IMPORTANT]
> Pay extra attention to the `--authorized-operator` flag. This is the address that will be authorized to sign
> commitments for your validators and that will have restaked collateral bound to it.
>
> Make sure to have the private key of this address stored securely.
>
> It _does not need_ to be the same as the admin account, but you can use the same address if you want.

## 5. Register your operator in a restaking protocol

We support both `Symbiotic` and `Eigenlayer` as restaking protocols that can be used to provide collateral to
your operator address.

Here we provide a quick guide on how to register with both, but you can choose the one you prefer.

<details>
<summary>Guide to register with Symbiotic</summary>

First, you'll need to install the [Symbiotic CLI](https://docs.symbiotic.fi/guides/cli/).
Then you can follow these steps to register your operator:

1. Register your operator address as a Symbiotic operator with
   [register-operator](https://docs.symbiotic.fi/guides/cli/#register-operator):

   ```bash
   python3 symb.py register-operator \
       --private-key <operator_private_key> \
       --chain holesky \
       --provider http://localhost:8545
   ```

2. Opt-in to the Bolt network with your operator address with
   [opt-in-network](https://docs.symbiotic.fi/guides/cli/#opt-in-network):

   Note: `0xb017...D2a4` is the Bolt symbiotic network address on Holesky.
   You can find the full list of deployments
   [here](https://github.com/chainbound/bolt/blob/unstable/bolt-contracts/config/holesky/deployments.json).

   ```bash
   python3 symb.py opt-in-network 0xb017002D8024d8c8870A5CECeFCc63887650D2a4 \
       --private-key <operator_private_key> \
       --chain holesky \
       --provider http://localhost:8545
   ```

3. Opt-in to any vault you want to use with [opt-in-vault](https://docs.symbiotic.fi/guides/cli/#opt-in-vault):

   [Here](https://github.com/chainbound/bolt/tree/unstable/testnets/holesky#on-chain-registration)
   is a list of the available vaults. We recommend using the `wETH` vault address for testing
   if you are not familiar with vault policies.

   The wETH vault is deployed at: `0xC56Ba584929c6f381744fA2d7a028fA927817f2b`

   ```bash
   python3 symb.py opt-in-vault <vault_address> \
       --private-key <operator_private_key> \
       --chain holesky \
       --provider http://localhost:8545
   ```

4. Deposit collateral into the vault you opted-in to with
   [deposit](https://docs.symbiotic.fi/guides/cli/#deposit):

   Here you can re-use the same vault address as above. The amount should be in ETH (e.g. '1' for 1 ETH).
   You MUST set the `on_behalf_of` address (i.e. the third argument in the below command) to your **operator** address.

   ```bash
   python3 symb.py deposit <vault_address> <amount> <operator_address> \
       --private-key <operator_private_key> \
       --chain holesky \
       --provider http://localhost:8545
   ```

5. Finally register into the BoltManager contract with `bolt` CLI:

   - NOTE: The `--operator-rpc` flag MUST be set to a PUBLICLY ACCESSIBLE URL. This is where your bolt-sidecar will
     receive commitment requests from users and reply with signed commitments. For instance, you can simply use your IP
     address and port (e.g. `--operator-rpc http://<public_ip>:<port`) AND make sure to open the <port> on your firewall.
     The <port> here refers to the port where the bolt-sidecar commitments-api server is running.
     By default it is `8017` and can be changed in the sidecar configuration file.
   - NOTE: If you are using a firewall such as `ufw`, you can open the port with the following command:
     `sudo ufw allow from <your_ip> to any port 8017`.
   - WARNING: Do NOT set the `--operator-rpc` flag to `localhost` or things like `infura.io` as they will not work.

   ```bash
   bolt operators symbiotic register \
       --rpc-url http://localhost:8545 \
       --operator-private-key <operator_private_key> \
       --operator-rpc <operator_rpc_url>
   ```

6. Check your operator status to ensure everything is set up correctly:

   ```bash
   bolt operators symbiotic status \
       --rpc-url http://localhost:8545 \
       --address <operator_address>
   ```

</details>

<details>
<summary>Guide to register with Eigenlayer</summary>

First, you need to install the
[Eigenlayer CLI](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation#cli-installation).

1. If you're not registered as an Eigenlayer operator yet, you need to do so by following
   [their official guide](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation#operator-configuration-and-registration).

   ```bash
   eigenlayer operator register operator.yaml
   ```

2. Deposit collateral into an Eigenlayer Strategy using the bolt CLI:

   - NOTE: this command will call the [`StrategyManager.depositIntoStrategy`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/testnet-holesky/src/contracts/core/StrategyManager.sol#L303-L322) function in the Eigenlayer contracts.

   ```bash
   bolt operators eigenlayer deposit \
         --rpc-url http://localhost:8545 \
         --operator-private-key <operator_private_key> \
         --strategy <strategy_name> \
         --amount <amount>
   ```

   Where:

   - `--rpc-url` is the URL of the Ethereum node to send transactions to (e.g. Geth)
   - `--operator-private-key` is the private key of your registered operator address
   - `--strategy` is the **NAME** of the strategy to deposit into. [possible values: st-eth, r-eth, w-eth, cb-eth, m-eth].
   - `--amount` is the amount to deposit into the strategy (in ETH) (e.g. '1' for 1 ETH).

3. Register into the Bolt AVS:

   - NOTE: The `--operator-rpc` flag MUST be set to a PUBLICLY ACCESSIBLE URL. This is where your bolt-sidecar will
     receive commitment requests from users and reply with signed commitments. For instance, you can simply use your IP
     address and port (e.g. `--operator-rpc http://<public_ip>:<port`) AND make sure to open the <port> on your firewall.
     The <port> here refers to the port where the bolt-sidecar commitments-api server is running.
     By default it is `8017` and can be changed in the sidecar configuration file.
   - NOTE: If you are using a firewall such as `ufw`, you can open the port with the following command:
     `sudo ufw allow from <your_ip> to any port 8017`.
   - WARNING: Do NOT set the `--operator-rpc` flag to `localhost` or things like `infura.io` as they will not work.

   ```bash
    bolt operators eigenlayer register \
        --rpc-url http://localhost:8545 \
        --operator-private-key <operator_private_key> \
        --operator-rpc <operator_rpc> \
        --salt <SALT> \
        --expiry <EXPIRY>
   ```

   Where:

   - `--rpc-url` is the URL of the Ethereum node to send transactions to (e.g. Geth)
   - `--operator-private-key` is the private key of your registered operator address
   - `--operator-rpc` is the URL of the operator's RPC server (e.g. `http://<ip>:<port>`)
   - `--salt` is a unique 32 bytes value to add replay attacks. To generate one (on MacOS or linux)
     you can run:

     ```bash
     echo -n "0x"; head -c 32 /dev/urandom | hexdump -e '32/1 "%02x" "\n"'
     ```

   - `--expiry` is the timestamp of the signature expiry in seconds.
     To generate it on both Linux and MacOS run the following command, replacing <EXPIRY_TIMESTAMP>
     with the desired timestamp:

     ```bash
     echo -n "0x"; printf "%064x\n" <EXPIRY_TIMESTAMP>
     ```

4. Check your operator status to ensure everything is set up correctly:

   ```bash
   bolt operators eigenlayer status \
       --rpc-url http://localhost:8545 \
       --address <operator_address>
   ```

</details>

## 6. Start the Bolt Sidecar + Mev-Boost setup

There are two modes in which the Bolt-sidecar can be run:

1. Docker mode (recommended)
2. Commit-boost mode

In this section we're going to cover the Docker mode, while the Commit-boost mode is covered in a
separate guide [here](./commit-boost/README.md) in detail.

### Docker mode

First, change directory to the `testnets/holesky` folder in the bolt repository you cloned in step 1:

```bash
cd testnets/holesky
```

In this directory you will find a `docker-compose.yml` file that you can use to start the Bolt-sidecar.
But before doing that, you will need to change the configuration file to match your setup.

To get started with the configuration, copy the example file:

```bash
cp bolt-sidecar.env.example bolt-sidecar.env
```

<details>
<summary>Here is a brief explanation of some of the less-obvious fields in the `bolt-sidecar.env` file:</summary>

- `BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY`: this is the private key of the operator address that you registered in the
  restaking protocol in the previous steps. This is the key that will be used to sign commitments for your validators.
- `BOLT_SIDECAR_BUILDER_PRIVATE_KEY`: this can be any valid BLS private key. You can generate one by visiting
  https://iancoleman.io/eip2333/ and pressing the GENERATE button.

The section "signing options" is by far the most complex part of the configuration file.
It is used to configure how Bolt protocol understands and authenticates your validators.

Although this is a quick guide, delegation must be understood correctly in order to be setup properly.
Here is a quick rundown of how it works:

The bolt-sidecar needs to know which validators it is controlling (aka, which validators it can sign commitments
on behalf of). Otherwise it may sign commitments for random validators which would get you slashed.

We could use the validator keys directly to do this, but that would entail loading them into the bolt-sidecar,
which is not the best in terms of security and operational practices.

For this reason, the bolt-sidecar uses a delegation mechanism that allows it to authenticate a different key
(the "delegatee") as a valid signer for a given validator. All we need to do is use the validator key once
to sign a message that essentially says "I authorize this other key to sign commitments on my behalf".

This way, operators don't need to use their validator secret keys in their online sidecar setup anymore.

This is by far the most recommended way to set up the bolt-sidecar.

In order to create and use these delegations, you can follow these steps:

1. Use the `bolt` CLI to generate signed delegation message for your validators:

   - Note: this step is similar to the `bolt pubkeys` command used in step 3 of this quick guide.
   - Note: this command can be run _offline_.
   - Note: you can generate a fresh BLS keypair [here](https://iancoleman.io/eip2333/) if necessary

   ```bash
    bolt delegate --delegatee-pubkey <delegatee_pubkey> local-keystore --path <validators_path> --password-path <secrets_path>
   ```

   Similarly, you can use `dirk` as the source if you are using a remote Dirk instance as opposed to a local keystore.

   This command will output a "delegations.json" file in the current directory.

2. Open the `bolt-sidecar.env` file and set:

   - `BOLT_SIDECAR_CONSTRAINT_PRIVATE_KEY`: the private key of which the public key was used to generate the delegation message
     (as `--delegatee-pubkey` in the previous step).
   - `BOLT_SIDECAR_DELEGATIONS_PATH`: `delegations.json` (name of the file generated in the previous step).

That's it! You can proceed to the next step.

</details>

After you've filled out the sidecar configuration, you can do the same with the `mev-boost` configuration:

```bash
cp mev-boost.env.example mev-boost.env
```

And fill out the values in the `mev-boost.env` file as well.

- NOTE: the config file comes with relay URLs already set up for you. Feel free to change them if
  you only want to use some specific relays.

Once the config files are in place, make sure you have Docker running and then start the docker compose:

```bash
docker compose --env-file bolt-sidecar.env up -d
```

The docker compose setup comes with various observability tools, such as Prometheus and Grafana.
It also comes with some pre-built dashboards which you can find at `http://localhost:28017`.
