

# Requirements and setup

- [Docker engine](https://docs.docker.com/engine/install/)(`v4.41.2`) installed and running
- [Just](https://github.com/casey/just) installed
- [Kurtosis CLI](https://docs.kurtosis.com/install/)(`0.88.16`) installed
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed
- [Rust & Cargo](https://www.rust-lang.org/tools/install) installed

> [!NOTE]
> After installing Docker v4.41.2, you need to increase the RAM allocation to maximum in Docker Settings.

> [!NOTE]
> The Kurtosis CLI version tested is `0.88.16`. Some issues may arise if you are
> using a different version.
>
> [Please make sure to install the correct version](https://docs.kurtosis.com/install-historical/).

Then, clone this repository and navigate to the root directory of the project:

```shell
git clone git@github.com:radiusxyz/bolt.git && cd bolt
git checkout dev
```

# Running the devnet

1. Build all necessary docker images locally first:
   ```shell
   just build-local-images
   ```

2. Spin up the kurtosis devnet on your machine:
   ```shell
   just up
   ```
   
   If you encounter architecture-related errors, use:
   ```shell
   DOCKER_DEFAULT_PLATFORM=linux/amd64 just up
   ```

(The MEV-Boost / Commit-Boost option can be selected in the [Kurtosis config](./scripts/kurtosis_config.yaml) using `mev_boost_image` or `bolt_boost_image`.)

When the devnet starts successfully, you should see logs similar to the ones shown below:

![Devnet Success Logs](./.github/assets/devnet-success-logs.png)


# The following sections are from the original Bolt README and describe the general functionality and structure of the Bolt protocol.

<div align="center">
  <picture>
    <source srcset="./.github/assets/bolt-logo-wm-dark.png" media="(prefers-color-scheme: dark)">
    <source srcset="./.github/assets/bolt-logo-wm-light.png" media="(prefers-color-scheme: light)">
    <img src="./.github/assets/bolt-logo-wm-light.png" alt="BOLT" width="450px">
  </picture>
</div>

<div align="center">

[![Docs](https://img.shields.io/badge/Docs-7B36ED?style=for-the-badge&logo=gitbook&logoColor=white)][docs]
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)][twitter]
[![Discord](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)][discord]

</div>

> [!IMPORTANT]
> Bolt is an implementation of permissionless proposer commitments that is fully compatible with PBS.
> In its essence, it consists in a fork of the MEV-Boost stack that allows users to request commitments
> like preconfirmations from proposers, and then adds a way for proposers to commit to transaction
> inclusion in a way that is verifiable on-chain.

<!-- vim-markdown-toc Marked -->

- [Requirements and setup](#requirements-and-setup)
- [Running the devnet](#running-the-devnet)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
  - [Additional components](#additional-components)
- [Kurtosis Devnet](#kurtosis-devnet)
  - [Requirements and setup](#requirements-and-setup)
  - [Running the devnet](#running-the-devnet)
  - [Stopping the devnet](#stopping-the-devnet)
- [License](#license)

<!-- vim-markdown-toc -->

## How it works

The technical flow of Bolt can be summarized in the following steps:

1. Users submit transactions to an RPC endpoint that will forward them to the
   proposer opted-in to Bolt in the beacon chain lookahead window.
2. The proposer can accept this request and turn it into a _commitment_ relative to the
   block that it is going to propose. This commitment acts as guarantee of inclusion of
   the transaction in the block, also known as a _preconfirmation_.
3. Near the time of block proposal, the proposer will share the list of committed transactions
   with the relays that are connected to block builders. This list is called a _constraint_.
4. Builders subscribe to proposer constraints in real time through a new relay
   streaming endpoint to keep informed about the outstanding preconfirmations.
5. Builders build valid blocks that adhere to all _constraints_, and append inclusion
   proofs together with the bids to the relay for trustless verification.
6. When it's time to propose a block, the proposer will fetch the best valid bid
   from the relay, and verify its inclusion proofs locally before signing the header.
7. If the constraints are respected, the proposer can propose the payload as usual
   by sending the signed header back to the relay. If not, the proposer can self-build
   a payload and propose it directly instead.

<details>
<summary>Here is a diagram illustrating the flow explained above:</summary>

```mermaid
sequenceDiagram
    participant Beacon Node as beacon node
    participant Bolt Sidecar as bolt-sidecar
    participant MEV-Boost as mev-boost
    participant PBS Relay as pbs relay

    Beacon Node->>Bolt Sidecar: /eth/v1/builder/header
    Note over Beacon Node, Bolt Sidecar: when it's time, the proposer's beacon node will ask for an externally built payload

    Bolt Sidecar->>MEV-Boost: /eth/v1/builder/header
    MEV-Boost->>PBS Relay: /eth/v1/builder/header_with_proofs
    PBS Relay->>MEV-Boost: ExecutionPayloadHeader + InclusionProofs
    MEV-Boost->>Bolt Sidecar: ExecutionPayloadHeader + InclusionProofs

    alt Inclusion proofs sent by the relay are VALID
        Bolt Sidecar->>Beacon Node: ExecutionPayloadHeader
        Bolt Sidecar->>MEV-Boost: /eth/v1/builder/blinded-blocks
        MEV-Boost->>PBS Relay: /eth/v1/builder/blinded-blocks
        Note over MEV-Boost, PBS Relay: the relay can now broadcast the full payload.
    else Inclusion proofs sent by the relay are INVALID
        PBS Relay->>MEV-Boost: nil response
        Bolt Sidecar->>Beacon Node: bolt-sidecar will generate a fallback ExecutionPayload that follows all constraints committed to by the proposer.
        Bolt Sidecar->>MEV-Boost: /eth/v1/builder/blinded-blocks
        MEV-Boost->>PBS Relay: /eth/v1/builder/blinded-blocks
        PBS Relay->>Beacon Node: ExecutionPayload
        Note over Beacon Node, Bolt Sidecar: after receiving the payload, the beacon node will broadcast it to the beacon chain p2p network.
    end
```

</details>

## Project structure

This repository contains most of the necessary components of the Bolt protocol stack.
In particular, the core components are:

- [**Bolt Sidecar**](./bolt-sidecar/): New validator software (akin to [mev-boost][fb-mev-boost])
  that handles the receipt of preconfirmation requests from users, translates them
  into _constraints_, and forwards them to relays. Additionally, it handles the
  fallback logic to produce a block locally when relays send invalid inclusion proofs.
- [**Bolt Contracts**](./bolt-contracts/): A set of smart contracts for peripheral functionality
  such as proposer registration and permissionless dispute resolution for attributable faults.
- [**Bolt Boost**](./bolt-boost/): A [Commit-Boost][commit-boost] module that implements the Constraints-API.
- [**Bolt CLI**](./bolt-cli/): A CLI tool to interact with Bolt components in a safe and easy way.
- [**Boltup**](./boltup/): Script to install the `bolt` CLI tool on any machine with a single command.
- [**Testnets**](./testnets/): A set of guides and scripts to deploy the Bolt contracts on testnets.
- [**Scripts**](./scripts/): A collection of scripts to build and run the Kurtosis devnet locally.

### Additional components

Bolt also relies on a few external components that are not part of this repository:

- [**Ethereum Package**](https://github.com/chainbound/ethereum-package): A fork of the Kurtosis
  Ethereum package with custom components for Bolt.
- [**Helix Relay**](https://github.com/chainbound/helix): A fork of the [Gattaca Helix][helix] relay that
  implements the Constraints API to proxy requests from the Bolt Sidecar to the connected builders.
- [**Bolt Builder**](https://github.com/chainbound/bolt-builder): A fork of the [Flashbots builder][fb-builder] that
  subscribes to new constraints from relays, builds blocks that respect them, and
  includes the necessary proofs of inclusion in the bids submitted to relays.
- [**Bolt MEV-Boost**](https://github.com/chainbound/bolt-mev-boost): A fork of the [Flashbots MEV-Boost][fb-mev-boost]
  sidecar that includes new API endpoints to proxy requests from the Bolt Sidecar to the connected relays.

<details>
<summary>List of legacy components that are not updated to the latest version of Bolt:</summary>

- [**Web demo**](https://github.com/chainbound/bolt-web-demo-legacy): A simple web interface to interact
  with the Bolt Sidecar and submit preconfirmation requests to proposers for inclusion in blocks.
- [**MEV-Boost-Relay**](https://github.com/chainbound/bolt-mev-boost-relay): A fork of the Flashbots
  [MEV-Boost relay][fb-relay] that includes new API endpoints to proxy requests from the Bolt Sidecar
  to the connected builders.

</details>

## Kurtosis Devnet

We are using a forked [Kurtosis][kurtosis] devnet stack, with custom Docker images
for the core components outlined above. The exact version of the Ethereum-package used
in our devnet can be seen [here](https://github.com/chainbound/ethereum-package).

### Requirements and setup

8GB of RAM and a modern laptop CPU are recommended to run the devnet efficiently,
but it should work on most machines. Please [Open an issue][new-issue] if you encounter any problems.

Make sure you have the following requirements on your machine:

- [Docker engine](https://docs.docker.com/engine/install/) installed and running
- [Just](https://github.com/casey/just) installed
- [Kurtosis CLI](https://docs.kurtosis.com/install/) installed
- [Foundry](https://book.getfoundry.sh/getting-started/installation) installed
- [Rust & Cargo](https://www.rust-lang.org/tools/install) installed
- [`cargo nextest`](https://nexte.st/)

> [!NOTE]
> The Kurtosis CLI version tested is `0.88.16`. Some issues may arise if you are
> using a different version.
>
> [Please make sure to install the correct version](https://docs.kurtosis.com/install-historical/).

Then, clone this repository and navigate to the root directory of the project:

```shell
git clone git@github.com:chainbound/bolt.git && cd bolt
```

### Running the devnet

Running the devnet is straightforward once you have the requirements
installed. Just run the following commands in your terminal:

```shell
# build all necessary docker images locally first
just build-local-images

# spin up the kurtosis devnet on your machine
just up
```

**Commit-Boost support**

The devnet by default will run using a fork of MEV-Boost which supports
the [Constraints-API](https://docs.boltprotocol.xyz/technical-docs/api/builder). Bolt also
supports [Commit-Boost][commit-boost] by providing a compatible MEV-Boost module
called _Bolt-Boost_ that implements the Constraints-API. To use it in the devnet
add the appropriate `bolt_boost_image` in the `kurtosis_config.yaml` file:

```yaml
# ... the rest of the file
mev_params:
  # Bolt-specific images:
  # Adding the `bolt_boost_image` will start the devnet with Bolt-Boost
  # instead of MEV-Boost
  bolt_boost_image: ghcr.io/chainbound/bolt-boost:v0.4.0-alpha
  # ... the rest of the `mev_params`
```

### Stopping the devnet

To stop the devnet, run the following command:

```shell
# if you want to simply stop all running containers
just down

# if you want to remove all the data and stop the Kurtosis engine
just clean
```

> [!NOTE]
> Remember to shut down the devnet environment when you are done with it, as it
> consumes significant resources (CPU & RAM) on your machine.

## License

MIT. Forked repositories have their own licenses.

<!-- Links -->

[twitter]: https://twitter.com/boltprotocol_
[discord]: https://discord.gg/pK8GgjxYQS
[docs]: https://docs.boltprotocol.xyz/
[new-issue]: https://github.com/chainbound/bolt/issues/new
[fb-mev-boost]: https://github.com/flashbots/mev-boost
[fb-relay]: https://github.com/flashbots/mev-boost-relay
[fb-builder]: https://github.com/flashbots/builder
[kurtosis]: https://www.kurtosis.com/
[helix]: https://github.com/gattaca-com/helix
[commit-boost]: https://commit-boost.github.io/commit-boost-client/
