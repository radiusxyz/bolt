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

# 2. get the native architecture name (first part of the target triple)
NATIVE_ARCH=$(uname -m)
if [[ "$(uname)" == "Darwin" && "$NATIVE_ARCH" == "arm64" ]]; then
    NATIVE_ARCH="aarch64"
fi

# 3. build the binary:
# - if the target is the same as the native architecture, build with cargo
# - otherwise, build with cargo-zigbuild
if [[ "$TARGE_ARCH" == "$NATIVE_ARCH-unknown-linux-gnu" ]]; then
    cd $PACKAGE && cargo build --target $TARGE_ARCH --release 
else
    cd $PACKAGE && cargo zigbuild --target $TARGET_ARCH --profile release
fi

# 4. copy the binary to the output directory
mkdir -p dist/bin/$OUT_DIR
cp $PACKAGE/target/$TARGET_ARCH/release/$PACKAGE dist/bin/$OUT_DIR/$PACKAGE

echo "Built $PACKAGE for $TARGET_ARCH"
