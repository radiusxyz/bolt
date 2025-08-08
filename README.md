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
git checkout main
```

# Running the devnet

1. Build all necessary docker images locally first:
   ```shell
   just build-local-images
   ```

2. Pull the smart-contract-verifier image with linux/amd64 platform compatibility:
   ```shell
   docker pull --platform=linux/amd64 ghcr.io/blockscout/smart-contract-verifier:v1.6.0
   ```


3. Spin up the kurtosis devnet on your machine:
   ```shell
   just up
   ```
   
   If you encounter architecture-related errors, use:
   ```shell
   DOCKER_DEFAULT_PLATFORM=linux/amd64 just up
   ```

4. Send preconfirmation test scenario: `just send-preconfs-test-scenario`

   This command runs an integrated test scenario that demonstrates the complete exclusion → first inclusion flow:
   
   - **Account Funding**: Automatically funds test accounts with ETH before running the scenario
   - **Exclusion Requests**: Sends multiple exclusion requests from different signers to register access list constraints
   - **First Inclusion Request**: The winning searcher (who sent exclusion requests early) gets first access to previously excluded states
   - **Atomic Processing**: Validates that exclusion constraints are enforced and first inclusion requests access the correct states
   
   The scenario simulates real MEV searcher behavior where searchers first exclude competing transactions from accessing certain states, then claim first inclusion rights to those states for their own transactions.

(The MEV-Boost / Commit-Boost option can be selected in the [Kurtosis config](./scripts/kurtosis_config.yaml) using `mev_boost_image` or `bolt_boost_image`.)

When the devnet starts successfully, you should see logs similar to the ones shown below:

![Devnet Success Logs](./.github/assets/devnet-success-logs.png)

> [!TIP]
> After 4 epochs, please use CLI: `just send-preconfs-test-scenario`


### [Bolt readme](https://github.com/chainbound/bolt/blob/unstable/README.md)
