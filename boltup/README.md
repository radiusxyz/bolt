# boltup

A simple installer script for the [bolt CLI](../bolt-cli).

## Usage

Install `boltup` by running the following command:

```sh
curl -L https://raw.githubusercontent.com/chainbound/bolt/unstable/boltup/install.sh | bash
```

After the installation is complete, you can run `boltup` to install or update the bolt CLI tool on your system.

```sh
boltup --tag [version]

# Example
boltup --tag v0.1.0
```

After the installation is complete, you can run `bolt` to use the bolt CLI tool.

```sh
bolt --help
```

## Aknowledgements

This script is based on [Foundryup](https://book.getfoundry.sh/getting-started/installation#using-foundryup)
