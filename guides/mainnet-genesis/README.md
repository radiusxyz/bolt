# Mainnet Genesis Instructions

This document provides instructions for operators to start integrating bolt on Mainnet.

## What does "Mainnet Genesis" mean?

Mainnet Genesis is our first step of releasing bolt on Ethereum Mainnet. At this stage,
we are exclusively launching _restaking integrations with EigenLayer and Symbiotic_
for node operators to start opting into bolt.

The following sections are divided based on the restaking protocol you are using.

- [EigenLayer Operators](#eigenlayer-operators)
- [Symbiotic Operators](#symbiotic-operators)

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

### Step 1: Register as an EigenLayer operator (if you haven't already)

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

### Step 3 (optional): Deposit collateral in EigenLayer strategies

You can already start depositing collateral for the AVS through one of the
whitelisted EigenLayer strategies. Here is a list of the strategies you can use:

- [StEth](https://etherscan.io/address/0x93c4b944D05dfe6df7645A86cd2206016c51564D)
<!-- TODO: add strategies -->

If you wish to use a different strategy, please reach out to us (at `dev@chainbound.io`
or through [Discord](https://discord.gg/G5BJjCD9ss)/[X](https://x.com/boltprotocol_))
and we will consider adding it to the whitelist. Please note that we only accept
ETH-derivative strategies currently.

Depositing as a staker is done through the [StrategyManager](https://github.com/Layr-Labs/eigenlayer-contracts/blob/ecaff6304de6cb0f43b42024ad55d0e8a0430790/src/contracts/core/StrategyManager.sol#L94-L100)
contract and is out of the scope of this guide. Please check out the official EigenLayer
[delegation guide](https://docs.eigenlayer.xyz/eigenlayer/restaking-guides/restaking-user-guide/liquid-restaking/restake-lsts)
for more information.

Currently (as of 2025-01-23) the EigenLayer ELIP-002 update is not deployed yet, so there
is no way to [join OperatorSets and allocate slashable magnitudes](https://docs.eigenlayer.xyz/eigenlayer/operator-guides/operator-sets#unique-stake-allocation--deallocation) to the AVS.

Once the EigenLayer ELIP-002 update is deployed on Mainnet, you will be able to join the bolt OperatorSet
and allocate slashable magnitudes to the AVS as you see fit.

## Symbiotic Operators
> [!NOTE]
> You need to be a registered Symbiotic operator in order to proceed.
> If you're not registered yet, follow [this guide](https://docs.symbiotic.fi/handbooks/operators-handbook#actions-in-symbiotic-core) in the
> Symbiotic docs.

### Step 1: Opt in to the Bolt Symbiotic Network
As an operator, you need to opt in to our network. This is the `opt-in-network` command in the CLI ([docs](https://docs.symbiotic.fi/handbooks/operators-handbook#through-cli)).

> [!IMPORTANT]
> Our network address is **`0xA42ec46F2c9DC671a72218E145CC13dc119fB722`**.

Example:
```bash
python symb.py --chain mainnet opt-in-network 0xA42ec46F2c9DC671a72218E145CC13dc119fB722 --private-key $YOUR_OPERATOR_PRIVATE_KEY
```

### Step 2: Register your operator with Bolt

To register in bolt's Symbiotic Network middleware contract, you can use this bolt CLI command:

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

### Step 3: Deposit collateral in Symbiotic Vaults

As a staker, you can deposit collateral in a vault. Depending on the type of vault,
there are some actions needed before your operator shares are updated/visible in **bolt**.

Regardless of the type of vault, we have to activate & whitelist the vault on our network.
Please reach out to us through the **Bolt Node Operator Working Group: Cohort 1** Telegram channel, 
or at [dev@chainbound.io](mailto:dev@chainbound.io)

#### OperatorSpecific and OperatorNetworkSpecific Vaults
- **Us**: whitelist vault
- **Operator**: Deposit collateral in the vault ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#deposit-to-vault))
- **Vault manager**: set network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#network-onboarding))

#### FullRestake and NetworkRestake Vaults
- **Us**: whitelist vault
- **Operator**: Deposit collateral in the vault ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#deposit-to-vault))
- **Vault manager**: set network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#network-onboarding))
- **Vault manager**: set operator network limit on the vault delegator ([guide](https://docs.symbiotic.fi/handbooks/vaults-handbook#operator-onboarding))
