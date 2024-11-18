#!/bin/bash

# Support script to build cross-platform binaries
# 
# Usage: ./build-cross-binary.sh <package> <target_arch> <out_dir>
# Example: ./build-cross-binary.sh bolt-sidecar x86_64-unknown-linux-gnu amd64

# Exit immediately if a command fails
set -e

# --- Variables ---

# Name of the package to build
PACKAGE=$1
# Target architecture to build for
TARGET_ARCH=$2
# Output directory for the binary
OUT_DIR=$3

# Building cross compiled binaries requires the OpenSSL headers for the target architecture.
# If not present, they must be installed manually and their paths set here.
X86_OPENSSL_PATH="/usr/include/x86_64-linux-gnu/openssl"
AARCH64_OPENSSL_PATH="/usr/include/aarch64-linux-gnu/openssl"

# --- Main script ---

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

# build "bolt-sidecar" with "cross" as it's the only working method for now.
if [[ "$PACKAGE" == "bolt-sidecar" ]]; then
    echo "Building $PACKAGE with cross"
    cross build --release --target $TARGET_ARCH
fi

# build other packages with cargo directly
if [[ "$TARGET_ARCH" == "aarch64-unknown-linux-gnu" ]]; then
    if [ ! -d $AARCH64_OPENSSL_PATH ]; then
        echo "Error: Cross-compiled OpenSSL libraries not found at $X86_OPENSSL_PATH"
        exit 1
    fi

    echo "Building $PACKAGE for $TARGET_ARCH"
    (
        cd $PACKAGE
        export CC="aarch64-linux-gnu-gcc"
        export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
        export CFLAGS_aarch64_unknown_linux_gnu=""
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"

        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$AARCH64_OPENSSL_PATH"
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR="$AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/include"
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR="$AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_DIR/lib"
        cargo build --release --target $TARGET_ARCH
    )
elif [[ "$TARGET_ARCH" == "x86_64-unknown-linux-gnu" ]]; then
    if [ ! -d $X86_OPENSSL_PATH ]; then
        echo "Error: Cross-compiled OpenSSL libraries not found at $X86_OPENSSL_PATH"
        exit 1
    fi

    echo "Building $PACKAGE for $TARGET_ARCH"
    (
        cd $PACKAGE
        export CC="x86_64-linux-gnu-gcc"

        export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$X86_OPENSSL_PATH"
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

echo "Successfully built $PACKAGE for $TARGET_ARCH and placed it in dist/bin/$OUT_DIR/$PACKAGE"
