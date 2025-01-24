# Mainnet Genesis Instructions

This document provides instructions for operators to start integrating bolt on Mainnet.

## What does "Mainnet Genesis" mean?

Mainnet Genesis is our first step of releasing bolt on Ethereum Mainnet. At this stage,
we are exclusively launching _restaking integrations with EigenLayer and Symbiotic_
for node operators to start opting into bolt.

The following sections are divided based on the restaking protocol you are using.

- [Prerequisites](#prerequisites)
- [EigenLayer Operators](#eigenlayer-operators)
  - [Step 1: Register as an EigenLayer operator](#step-1-register-as-an-eigenlayer-operator)
  - [Step 2: Register your operator into bolt's AVS](#step-2-register-your-operator-into-bolts-avs)
  - [Step 3: Deposit collateral](#step-3-deposit-collateral-optional)
  - [Deregistration](#deregistration)
- [Symbiotic Operators](#symbiotic-operators)
  - [Step 1: Opt in to the Bolt Symbiotic Network](#step-1-opt-in-to-the-bolt-symbiotic-network)
  - [Step 2: Register your operator with Bolt](#step-2-register-your-operator-with-bolt)
  - [Step 3: Deposit Collateral](#step-3-deposit-collateral-optional-1)
  - [Step 4: Post Deposit Actions](#step-4-post-deposit-actions)
  - [Deregistration](#deregistration-1)

> [!CAUTION]
> ONLY register operators as an EOA (no Safe or other multisig). Bolt will require you to have access
> to a singular private key for the operator, which contracts do not have.

## Prerequisites

To install the bolt CLI tool, you can either use our pre-built binaries or build it from source:

<details>
<summary>Install from pre-built binaries (recommended)</summary>

```bash
# download the bolt-cli installer
curl -L https://raw.githubusercontent.com/chainbound/bolt/unstable/boltup/install.sh | bash

# start a new shell to use the boltup installer
exec $SHELL

# install the bolt-cli binary
boltup --tag v0.1.3

# check for successful installation
bolt --help
```

</details>

<details>
<summary>Building from source</summary>

You will need the following dependencies to build the bolt CLI yourself:

- [Install Rust](https://www.rust-lang.org/tools/install)
- [Install Protoc](https://grpc.io/docs/protoc-installation/)

```bash
# Clone the repository if you haven't already
git clone https://github.com/chainbound/bolt && cd bolt

# Build the bolt CLI
cd bolt-cli
cargo install --force --path .

# check for successful installation
bolt --help
```

</details>

## EigenLayer Operators

> [!IMPORTANT]
> These instructions follow the latest EigenLayer deployment as of 2025-01-23
> corresponding to the [Rewards V2](https://github.com/Layr-Labs/eigenlayer-contracts/releases/tag/v0.5.4) release.

### Step 1: Register as an EigenLayer operator

You need to be a registered [EigenLayer operator](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-installation)
in order to start opting into any AVS. Make sure you have an active operator account to proceed.

### Step 2: Register your operator into bolt's AVS

To register in bolt's AVS contract, you can use this bolt CLI command:

```bash
bolt operators eigenlayer register \
    --rpc-url <your-rpc-url> \
    --operator-private-key <your-operator-private-key> \
    --extra-data <your-extra-data-string>
    # [OPTIONAL] --operator-rpc <your-operator-rpc-url>
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-private-key>` is the private key of the operator account you are using
- `<your-extra-data-string>` is any extra string you want to include in the registration,
  such as your operator name, website or a custom identifier
- `<your-operator-rpc-url>` is the URL of the bolt-sidecar RPC server you will be receiving
  preconfirmation requests on. By default, this is set to Chainbound's "bolt RPC" that acts
  as proxy for all operators. You can also change this setting at any time later on.

You can check your operator registration status with this command:

```bash
bolt operators eigenlayer status \
    --rpc-url <your-rpc-url> \
    --address <your-operator-address>
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-address>` is the Ethereum address of your operator

> [!NOTE]
> The operator registration should immediately go through, but it won't be active yet.
> The activation process takes 24 hours.

### Step 3: Deposit Collateral (Optional)

You can already start depositing collateral for the AVS through one of the
whitelisted EigenLayer strategies. Here is a list of the strategies you can use:

| Collateral | Strategy Address                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------------------------------------------ |
| `stETH`    | [`0x93c4b944D05dfe6df7645A86cd2206016c51564D`](https://etherscan.io/address/0x93c4b944D05dfe6df7645A86cd2206016c51564D)  |
| `rETH`     | [`0x1bee69b7dfffa4e2d53c2a2df135c388ad25dcd2`](https://etherscan.io/address/0x1bee69b7dfffa4e2d53c2a2df135c388ad25dcd2)  |
| `mETH`     | [`0x298afb19a105d59e74658c4c334ff360bade6dd2`](https://etherscan.io/address/0x298afb19a105d59e74658c4c334ff360bade6dd2)  |

<!-- TODO: add strategies -->

Please reach out to us through the **Bolt Node Operator Working Group: Cohort 1** Telegram channel (for Bolt NOs), 
or at [dev@chainbound.io](mailto:dev@chainbound.io) if you want to request a new strategy to be whitelisted. 

> [!NOTE]
> The strategy activation process takes 24 hours. You can deposit collateral immediately, but it won't show up until
> the activation period has passed.

Depositing as a staker is done through the [StrategyManager](https://github.com/Layr-Labs/eigenlayer-contracts/blob/ecaff6304de6cb0f43b42024ad55d0e8a0430790/src/contracts/core/StrategyManager.sol#L94-L100)
contract and is out of the scope of this guide. Please check out the official EigenLayer
[delegation guide](https://docs.eigenlayer.xyz/eigenlayer/restaking-guides/restaking-user-guide/liquid-restaking/restake-lsts)
for more information.

Currently (as of 2025-01-23) the EigenLayer ELIP-002 update is not deployed yet, so there
is no way to [join OperatorSets and allocate slashable magnitudes](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-sets#unique-stake-allocation--deallocation) to the AVS.

Once the EigenLayer ELIP-002 update is deployed on Mainnet, you will be able to join the bolt OperatorSet
and allocate slashable magnitudes to the AVS as you see fit.

To check your collateral, you can use the following command:

```bash
bolt operators eigenlayer status \
    --rpc-url <your-rpc-url> \
    --address <your-operator-address>
```

### Deregistration
Use the following command to deregister from bolt:

```bash
bolt operators eigenlayer deregister \
    --rpc-url <your-rpc-url> \
    --operator-private-key <your-operator-private-key> 
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-private-key>` is the private key of the operator account you are using

This will unlink your Symbiotic operator from the bolt middleware. 

## Symbiotic Operators
> [!NOTE]
> You need to be a registered Symbiotic operator in order to proceed.
> If you're not registered yet, follow [this guide](https://docs.symbiotic.fi/handbooks/operators-handbook#actions-in-symbiotic-core) in the
> Symbiotic docs.

### Step 1: Opt in to the Bolt Symbiotic Network
As an operator, you need to opt in to our network. This is the `opt-in-network` command in the CLI ([docs](https://docs.symbiotic.fi/handbooks/operators-handbook#through-cli)).

> [!IMPORTANT]
> Our network address is **`0xA42ec46F2c9DC671a72218E145CC13dc119fB722`** ([boltprotocol.eth](https://etherscan.io/address/boltprotocol.eth)).

Example:
```bash
python symb.py --chain mainnet opt-in-network 0xA42ec46F2c9DC671a72218E145CC13dc119fB722 --private-key $YOUR_OPERATOR_PRIVATE_KEY
```

### Step 2: Register your operator with Bolt
To register in the bolt Symbiotic Network middleware contract, use the following bolt CLI command:

```bash
bolt operators symbiotic register \
    --rpc-url <your-rpc-url> \
    --operator-private-key <your-operator-private-key> \
    --extra-data <your-extra-data-string>
    # [OPTIONAL] --operator-rpc <your-operator-rpc-url>
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-private-key>` is the private key of the operator account you are using
- `<your-extra-data-string>` is any extra string you want to include in the registration,
  such as your operator name, website or a custom identifier
- `<your-operator-rpc-url>` is the URL of the bolt-sidecar RPC server you will be receiving
  preconfirmation requests on. By default, this is set to Chainbound's "bolt RPC" that acts
  as proxy for all operators. You can also change this setting at any time later on.

This will make your operator readable to the Bolt smart contracts and off-chain infrastructure, as well as provide
a link between your operator signer and your deposited collateral.

You can check your operator registration status with this command:

```bash
bolt operators symbiotic status \
    --rpc-url <your-rpc-url> \
    --address <your-operator-address>
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-address>` is the Ethereum address of your operator

> [!NOTE]
> The operator registration should immediately go through, but it won't be active yet.
> The activation process takes 24 hours.

### Step 3: Deposit Collateral (Optional)

As a staker, you can deposit collateral in a vault. **Please note that this is not mandatory for mainnet genesis**.

Regardless of the type of vault, we have to activate & whitelist the vault on our network.
Please reach out to us through the **Bolt Node Operator Working Group: Cohort 1** Telegram channel (for NOs), 
or at [dev@chainbound.io](mailto:dev@chainbound.io) if you want to request a new vault to be whitelisted. 

We'll need the following information about your vault:
- Collateral
- Type
- Manager

Note that Bolt only works with collateral that are ETH derivatives right now.

After the vault has been whitelisted, you can deposit collateral in it. Please refer to the [Symbiotic docs](https://docs.symbiotic.fi/guides/cli#deposit)
on how to do that.

To check your collateral, you can use the following command:

```bash
bolt operators symbiotic status \
    --rpc-url <your-rpc-url> \
    --address <your-operator-address>
```

> [!NOTE]
> The vault activation process takes 24 hours. You can deposit collateral immediately, but it won't show up until
> the activation period has passed.

### Step 4: Post Deposit Actions
Depending on the type of vault, there are some actions needed before your operator shares are visible in bolt.
#### OperatorSpecific and OperatorNetworkSpecific Vaults
- **Us**: whitelist vault
- **Vault manager**: set network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#network-onboarding))

#### FullRestake and NetworkRestake Vaults
- **Us**: whitelist vault
- **Vault manager**: set network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#network-onboarding))
- **Vault manager**: set operator network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#operator-onboarding))

### Deregistration
Use the following command to deregister from bolt:

```bash
bolt operators symbiotic deregister \
    --rpc-url <your-rpc-url> \
    --operator-private-key <your-operator-private-key> 
```

where:

- `<your-rpc-url>` is the URL of the Ethereum RPC node you are using
- `<your-operator-private-key>` is the private key of the operator account you are using

This will unlink your Symbiotic operator from the bolt middleware. Note that you will still have to deregister in the Symbiotic contracts too.