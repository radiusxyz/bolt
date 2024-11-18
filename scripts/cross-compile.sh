#!/bin/bash

# Support script to build cross-platform binaries
# 
# Usage: ./build-cross-binary.sh <package> <target_arch> <out_dir>
# Example: ./build-cross-binary.sh bolt-sidecar x86_64-unknown-linux-gnu /dist/bin

# Exit immediately if a command fails
set -e

# Name of the package to build
PACKAGE=$1
# Target architecture to build for
TARGET_ARCH=$2
# Output directory for the binary
OUT_DIR=$3

# Check for required arguments
if [[ -z "$PACKAGE" || -z "$TARGET_ARCH" || -z "$OUT_DIR" ]]; then
    echo "Usage: $0 <package> <target_arch> <out_dir>"
    exit 1
fi

# 1. Install the toolchain if it's not already installed
if ! rustup target list | grep -q "^$TARGET_ARCH (installed)$"; then
    echo "Installing Rust target: $TARGET_ARCH"
    rustup target add "$TARGET_ARCH"
fi

# 2. Build the binary
if [[ "$TARGET_ARCH" == "aarch64-unknown-linux-gnu" ]]; then
    # For Arm64, use the cross-compiled version of OpenSSL.
    # NOTE: Adjust the paths for your setup if necessary.
    if [ ! -d /usr/include/aarch64-linux-gnu/openssl ]; then
        echo "Error: Cross-compiled OpenSSL libraries not found at /usr/include/aarch64-linux-gnu/openssl."
        exit 1
    fi

    echo "Building $PACKAGE for $TARGET_ARCH with cross-compiled OpenSSL"
    (
        cd $PACKAGE
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include/aarch64-linux-gnu/openssl
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/lib/aarch64-linux-gnu
        cargo build --release --target $TARGET_ARCH
    )
else
    echo "Building $PACKAGE for $TARGET_ARCH"
    (
        cd $PACKAGE
        cargo build --release --target $TARGET_ARCH
    )
fi

# 3. copy the binary to the output directory
mkdir -p dist/bin/$OUT_DIR
cp $PACKAGE/target/$TARGET_ARCH/release/$PACKAGE dist/bin/$OUT_DIR/$PACKAGE

echo "Successfully built $PACKAGE for $TARGET_ARCH and placed it in $DIST_DIR"
