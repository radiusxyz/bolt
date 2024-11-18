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
    # Use the cross-compiled version of OpenSSL.
    # NOTE: Adjust the paths for your setup if necessary.
    if [ ! -d /usr/include/aarch64-linux-gnu/openssl ]; then
        echo "Error: Cross-compiled OpenSSL libraries not found at /usr/include/aarch64-linux-gnu/openssl."
        exit 1
    fi

    echo "Building $PACKAGE for $TARGET_ARCH"
    (
        cd $PACKAGE
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="/usr/include/aarch64-linux-gnu/openssl"
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR="$AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/include"
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR="$AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/lib"
        cargo build --release --target $TARGET_ARCH
    )
else if [[ "$TARGET_ARCH" == "x86_64-unknown-linux-gnu" ]]; then
    # Use the cross-compiled version of OpenSSL.
    # NOTE: Adjust the paths for your setup if necessary.
    if [ ! -d /usr/include/x86_64-linux-gnu/openssl ]; then
        echo "Error: Cross-compiled OpenSSL libraries not found at /usr/include/x86_64-linux-gnu/openssl."
        exit 1
    fi

    echo "Building $PACKAGE for $TARGET_ARCH"
    (
        cd $PACKAGE
        export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="/usr/include/x86_64-linux-gnu/openssl"
        export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR="$X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/include"
        export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR="$X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/lib"
        cargo build --release --target $TARGET_ARCH
    )
else
    echo "Unsupported target architecture: $TARGET_ARCH"
    exit 1
fi

# 3. copy the binary to the output directory
mkdir -p dist/bin/$OUT_DIR
cp $PACKAGE/target/$TARGET_ARCH/release/$PACKAGE dist/bin/$OUT_DIR/$PACKAGE

echo "Successfully built $PACKAGE for $TARGET_ARCH and placed it in $DIST_DIR"
