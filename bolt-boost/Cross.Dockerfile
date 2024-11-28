# This image is meant to enable cross-architecture builds.
# It assumes the binary has already been compiled for `$TARGETPLATFORM` and is
# locatable in `./dist/bin/$TARGETARCH/$BINARY`.

# We need ubuntu 20.04 because more recent versions come with openssl3 
# and our binary depends on openssl 1.1.1 and installing 1.1.1 on new
# ubuntu versions is highly discouraged.
FROM --platform=$TARGETPLATFORM ubuntu:20.04

LABEL org.opencontainers.image.source=https://github.com/chainbound/bolt
LABEL org.opencontainers.image.licenses="MIT"

# Filled by docker buildx
ARG TARGETARCH

# Should be set by the caller when building the image
ARG BINARY

# We need to install ca-certificates to make HTTPS requests (only with ubuntu 20.04)
RUN apt-get update && apt-get install -y ca-certificates

COPY ./dist/bin/$TARGETARCH/$BINARY /usr/local/bin/bolt-boost

ENTRYPOINT ["/usr/local/bin/bolt-boost"]
