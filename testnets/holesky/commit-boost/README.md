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
2. Navigate to the directory containing this README: `cd bolt/testnets/holesky/commit-boost`
3. Copy the sidecar ENV example file: `cp bolt-sidecar.env.example bolt-sidecar.env`
4. Modify the ENV file to your liking: `vim bolt-sidecar.env`. The file is already commented to guide you
   through the process of setting up the sidecar.
5. (Optional) Modify the [`cb-bolt-config.toml`](./cb-bolt-config.toml) file if necessary. It should be fine as is.
6. Start the docker compose setup with `docker compose -f cb.docker-compose.yml up -d`

In order to connect your validators, you will need to set the builder endpoint to the Bolt-Sidecar API.

- By default this is exposed on port `18550` on the host machine and can be accessed at `http://localhost:18550`.
- For instance, on Lighthouse this is specified via the `--builder http://localhost:18550` flag.

## Observability

Commit-Boost comes with various observability tools, such as Prometheus, cadvisor, and Grafana.
It also comes with some pre-built dashboards, which can be found in the [`grafana`](./grafana/) directory.

To update these dashboards, run the following command from the [`commit-boost`](.) directory:

```shell
bash ./update-grafana.sh
```

In this directory, you can also find a Bolt dashboard, which will be launched alongside the other dashboards.
