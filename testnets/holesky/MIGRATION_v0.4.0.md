# `v0.4.0-alpha` Migration Guide

This document outlines a migration guide for upgrading bolt to v0.4.0-alpha, which contains some breaking changes. We'll start with an overview of the main changes.

- [Firewall delegation](#firewall-delegation)
- [New pricing model](#new-pricing-model)
- [**Required action**](#required-action)

### Firewall delegation
Firewall delegation allows proposers to set an external third party as their network entrypoint or *firewall*. It gets rid of the
requirement to expose an HTTP RPC endpoint for accepting inclusion requests (inbound), and instead subscribes to the configured firewall over a
websocket connection (outbound).

Some of the other duties of the firewall include:
- Spam and DoS prevention
- Pricing inclusion requests correctly (see more below)
- Communicating prices with consumers (wallets, users)

Currently, we operate a firewall RPC on Holesky at `wss://rpc-holesky.bolt.chainbound.io/api/v1/firewall_stream`.

Read more [here](https://x.com/boltprotocol_/status/1879571451621077413).

### New pricing model
This new release also comes with an upgraded, dynamic pricing model that's based on joint research by Nethermind and Chainbound.
The model is described in [this post](https://research.lido.fi/t/a-pricing-model-for-inclusion-preconfirmations/9136). In short,
it provides an estimate for the floor price an inclusion preconfirmation MUST have so that the proposer has a very minimal chance of
losing revenue by committing to it.

Our model varies slightly from the original description due to implementation details, which we'll cover in another document. Additionally,
the bolt-sidecar allows proposers to configure a **minimum profit** parameter that is added to the floor price in order to arrive at a total
priority fee.

Check out all release notes [here](https://github.com/chainbound/bolt/releases/tag/v0.4.0-alpha).

### Required action
Start by pulling in the changes:
```bash
# Optional
git clone --branch v0.4.0-alpha https://github.com/chainbound/bolt

# OR in your local repo
git pull && git checkout v0.4.0-alpha

# Navigate to the holesky directory
cd bolt/testnets/holesky
```

These changes are quite substantial, as they contain updated docker compose files & container versions, along with updated
configs:

##### Firewall delegation
- `BOLT_SIDECAR_FIREWALL_RPCS` is set by default, which means that the sidecar will run in firewall delegation mode.
- `BOLT_SIDECAR_PORT` controls whether to expose an HTTP endpoint instead of using firewall delegation. These 2 options are mutually exclusive.

##### Pricing
- `BOLT_SIDECAR_MIN_PRIORITY_FEE` has been replaced by `BOLT_SIDECAR_MIN_INCLUSION_PROFIT`, which is the amount of gwei
added to the floor price determined by the pricing model

##### Other
- `BOLT_SIDECAR_COMMITMENT_PRIVATE_KEY` has been renamed to `BOLT_SIDECAR_OPERATOR_PRIVATE_KEY`
- `BOLT_SIDECAR_MAX_COMMITMENTS_PER_SLOT` has been dropped, `BOLT_SIDECAR_MAX_COMMITTED_GAS` remains

These configuration values are present in [`bolt-sidecar.env.example`](./bolt-sidecar.env.example) or in [`sidecar-delegations-preset.env.example`](./presets/sidecar-delegations-preset.env.example). You can either copy those and update them to your required values,
or modify your existing config.

##### Config guidelines
- Don't set `BOLT_SIDECAR_MIN_INCLUSION_PROFIT` to something too high (1 gwei will work for now), or our simulated transaction sender will not send you any inclusion requests.
- Don't set `BOLT_SIDECAR_MAX_COMMITTED_GAS` to something higher than 15000000 (15 million, 50% of gas limit). Setting this to too high will drive up the floor price determined by the pricing model.
- If you're using firewall delegation (the default), you can remove any local firewall rules related to the Bolt public HTTP endpoint.
