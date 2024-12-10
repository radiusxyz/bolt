#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Make sure we're in the correct directory
cd /usr/local/bin

# Load the environment variables from the .env file.
source .env

# Override some of the environment variables provided by the user, even if
# provided via .env file, so that the volume mounts work as expected.
#
# The ":+" syntax replaces the environment variable with the alternate value
# only if set _and_ not empty.
# Reference: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/#interpolation-syntax
#
# Ensure these environment variables are either empty or set with the
# alternative values, overriding what's provided with the `--env-file` flag in
# the Docker Compose file and matching the volume mounts.
export BOLT_SIDECAR_DELEGATIONS_PATH="${BOLT_SIDECAR_DELEGATIONS_PATH:+/etc/delegations.json}"
export BOLT_SIDECAR_KEYSTORE_PATH="${BOLT_SIDECAR_KEYSTORE_PATH:+/etc/keystore}"
export BOLT_SIDECAR_KEYSTORE_SECRETS_PATH="${BOLT_SIDECAR_KEYSTORE_SECRETS_PATH:+/etc/secrets}"

./bolt-sidecar
