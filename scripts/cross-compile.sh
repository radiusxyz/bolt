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
#
# Note: everything so far can be built with zigbuild, except for bolt-boost 
# targeting x86_64-unknown-linux-gnu. As this is still unresolved, we handle
# this case separately by building the binary with cargo instead. This is less 
# than ideal, but it works and it's simple
if [[ $PACKAGE == "bolt-boost" && $TARGET_ARCH == "x86_64-unknown-linux-gnu" ]]; then
    echo "Building binary with cargo"
    (cd $PACKAGE && cargo build --target $TARGE_ARCH --release)
else
    echo "Building binary with cargo-zigbuild"
    (cd $PACKAGE && cargo zigbuild --target $TARGET_ARCH --profile release)
fi

# 3. copy the binary to the output directory
mkdir -p dist/bin/$OUT_DIR
cp $PACKAGE/target/$TARGET_ARCH/release/$PACKAGE dist/bin/$OUT_DIR/$PACKAGE

echo "Built $PACKAGE for $TARGET_ARCH"
