# Devcon Validators Launch Instructions

Validators can run Bolt through the bolt-sidecar commit-boost module.
You can get started with the docker-compose file available [here](./cb.docker-compose.yml).

Before being able to run it, you need to create a `.bolt-sidecar.env` file from the provided example:

```bash
cp .bolt-sidecar.example.env .bolt-sidecar.env
```

You can then modify the `.bolt-sidecar.env` file with your own configuration.

After you're done, you can start the setup with the following command
(from the same directory as the `cb.docker-compose.yml` file):

```bash
docker-compose -f cb.docker-compose.yml --env-file .cb.env up -d
```

Here is a schema of the setup:

```
beacon_node -> pbs_module -> bolt_sidecar -> relays
```

1. When it's time to propose a block, the beacon node will send a `get_header` request to its `builder` endpoint.
2. The builder endpoint is configured to be commit-boost's `pbs_module` which will forward the request to the `bolt_sidecar`
   which is configured as the only relay available.
3. The `bolt_sidecar` will then play the role of mev-boost and will forward the request to the actual connected relays.
4. The relays will send the best blinded header to the `bolt_sidecar` which will then forward the best one to the `pbs_module`.
5. The `pbs_module` will forward the header to the beacon node which will sign it and proceed with the `get_payload` flow.
