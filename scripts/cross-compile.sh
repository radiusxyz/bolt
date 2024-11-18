#!/bin/bash

# Support script to build cross-platform binaries
# 
# Usage: ./build-cross-binary.sh <package> <target_arch> <out_dir>
# Example: ./build-cross-binary.sh bolt-sidecar x86_64-unknown-linux-gnu /dist/bin

# Name of the package to build
PACKAGE=$1
# Target architecture to build for
TARGET_ARCH=$2
# Output directory for the binary
OUT_DIR=$3

# 1. install the toolchain if it's not already installed
if ! rustup target list | grep -q $TARGET_ARCH; then
    rustup target add $TARGET_ARCH
fi

# 2. build the binary.
if [[ $TARGET_ARCH == "aarch64-unknown-linux-gnu"]]; then
    # For Arm64, we need to use the cross-compiled version of openssl.
    # NOTE: we have hard-coded the installation path for these cross-compiled libraries for our dev box.
    (
        # Check if the cross-compiled openssl libraries are installed
        if [ ! -d /usr/include/aarch64-linux-gnu/openssl ]; then
            echo "Cross-compiled openssl libraries not found. Please install them."
            exit 1
        fi
    )
    (
        cd $PACKAGE
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/usr/include/aarch64-linux-gnu/openssl/include
        export AARCH64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/usr/include/aarch64-linux-gnu/openssl/lib
        cargo build --release --target $TARGET_ARCH
    )
else
    (
        # For x86 we don't need to do anything special
        cd $PACKAGE
        cargo build --release --target $TARGET_ARCH
    )
fi

# 3. copy the binary to the output directory
mkdir -p dist/bin/$OUT_DIR
cp $PACKAGE/target/$TARGET_ARCH/release/$PACKAGE dist/bin/$OUT_DIR/$PACKAGE

echo "Built $PACKAGE for $TARGET_ARCH"
