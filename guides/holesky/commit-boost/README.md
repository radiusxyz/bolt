# Holesky Commit-Boost x Bolt setup

This is a setup guide for running Bolt on Holesky using [Commit-Boost](https://commit-boost.github.io/commit-boost-client/) modules.

Here is a quick overview of the architecture described in [`cb.docker-compose.yml`](./cb.docker-compose.yml):

- `bolt-boost`: a Commit-Boost moodule built by the Bolt team that builds upon the standard PBS module and adds
  the [constraints API](https://docs.boltprotocol.xyz/technical-docs/api/builder).
- `bolt-sidecar`: a separate service, in the form of Commit-Boost "commit" module, that is responsible for
  signing incoming preconfirmation requests, managing local fallback blocks and keeping track of the state.
- `grafana`, `prometheus` and `cadvisor` periphery services for observability.

## Requirements

- An Ethereum validator node on the Holesky testnet
- A synced Holesky Geth client with access to the Engine API
- Docker and Docker Compose installed and running

## Setup

1. Clone the repository if you haven't already: `git clone https://github.com/chainbound/bolt`
2. Navigate to the directory containing this README: `cd bolt/guides/holesky/commit-boost`
3. Copy the sidecar ENV example file: `cp bolt-sidecar.env.example bolt-sidecar.env`
4. Modify the ENV file to your liking: `vim bolt-sidecar.env`. See [Sidecar Configuration](#sidecar-configuration).
5. (Optional) Modify the [`cb-bolt-config.toml`](./cb-bolt-config.toml) file if necessary. It should be fine as is.
6. Start the docker compose setup with `docker compose -f cb.docker-compose.yml up -d`

In order to connect your validators, you will need to set the builder endpoint to the Bolt-Sidecar API.

- By default this is exposed on port `18550` on the host machine and can be accessed at `http://localhost:18550`.
- For instance, on Lighthouse this is specified via the `--builder http://localhost:18550` flag.

### Sidecar Configuration

The `bolt-sidecar.env` file already contains detailed explanations of the available configuration options,
but here is a quick overview of the less-obvious ones:

- `BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY`: must match the private key associated with the Ethereum address that
  has been registered in the `BoltManager` on-chain contract. [See more here](../README.md#on-chain-registration).
- `BOLT_SIDECAR_BUILDER_PRIVATE_KEY`: can be any valid BLS secret key, as it is only used for tricking the beacon node
  into thinking that the local payloads came from an authenticated PBS source.
- `BOLT_SIDECAR_CONSTRAINT_PRIVATE_KEY`: is the private key used to sign the constraints API requests. We recommend using
  offline delegation in order to avoid using live validator keys for this purpose. [See more here](../README.md#delegations-and-signing-options-for-native-and-docker-compose-mode).
- `BOLT_SIDECAR_DELEGATIONS_PATH`: this should be kept as `/etc/delegations.json` if set, as it's only mapped in the docker
  container if using delegations. After generating delegations in the previous step, you can copy the `delegations.json` file
  in the same directory as the `bolt-sidecar.env` file and it will be picked up by the container.

## Observability

Commit-Boost comes with various observability tools, such as Prometheus, cadvisor, and Grafana.
It also comes with some pre-built dashboards, which can be found in the [`grafana`](./grafana/) directory.

To update these dashboards, run the following command from the [`commit-boost`](.) directory:

```shell
bash ./update-grafana.sh
```

In this directory, you can also find a Bolt dashboard, which will be launched alongside the other dashboards.
