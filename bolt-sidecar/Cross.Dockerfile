# This image is meant to enable cross-architecture builds.
# It assumes the binary has already been compiled for `$TARGETPLATFORM` and is
# locatable in `./dist/bin/$TARGETARCH/$BINARY`.

FROM --platform=$TARGETPLATFORM ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/chainbound/bolt
LABEL org.opencontainers.image.licenses="MIT"

# Filled by docker buildx
ARG TARGETARCH

# Should be set by the caller when building the image
ARG BINARY

COPY ./dist/bin/$TARGETARCH/$BINARY /usr/local/bin/bolt-sidecar

ENTRYPOINT ["/usr/local/bin/bolt-sidecar"]
