#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Override the environment variables provided by the user.
#
# The "+" syntax replaces the environment variable with the alternate valuee
# only if set.
# Reference: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#interpolation-syntax

# Ensure these environment variables are either empty or set with the
# alternative values, overriding what's provided with the `--env-file` flag in
# the Docker Compose file and matching the volume mounts.
export BOLT_SIDECAR_DELEGATIONS_PATH="${BOLT_SIDECAR_DELEGATIONS_PATH+/etc/delegations.json}"
export BOLT_SIDECAR_KEYSTORE_PATH="${BOLT_SIDECAR_KEYSTORE_PATH+/etc/keystore}"
export BOLT_SIDECAR_KEYSTORE_SECRETS_PATH="${BOLT_SIDECAR_KEYSTORE_SECRETS_PATH+/etc/secrets}"

/usr/local/bin/bolt-sidecar
