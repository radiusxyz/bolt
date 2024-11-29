# test data for the `bolt` CLI

- [`lighthouse`](./lighthouse/): A lighthouse-format keystore according to the [specs][lh-specs].
  It contains two directories: `validators` for the voting-keystores, and `secrets` for the passwords
  needed to decrypt the keypairs.

- [`dirk_single`](./dirk_single/): A directory containing test TLS certificates and keys for authenticating a single
  test [Dirk][dirk] server on localhost. The certificates are self-signed for test purposes and are not to be used
  in production.

- [`dirk_multi`](./dirk_multi/): A directory containing test TLS certificates and keys for authenticating multiple
  test [Dirk][dirk] servers on localhost, used in a distributed setup. The certificates are self-signed for test
  purposes and are not to be used in production.

[lh-specs]: https://lighthouse-book.sigmaprime.io/validator-management.html#automatic-validator-discovery
[dirk]: https://github.com/attestantio/dirk
