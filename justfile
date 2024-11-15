# display a help message about available commands
default:
  @just --list --unsorted

# spin up the bolt devnet
up:
	chmod +x ./scripts/start-devnet.sh
	./scripts/start-devnet.sh

# turn down the bolt devnet and remove the enclave
down:
	kurtosis enclave rm -f bolt-devnet

# remove all kurtosis data and stop the engine
clean:
	kurtosis clean --all
	kurtosis engine stop

# restart the bolt devnet with updated docker images
restart:
	@just down
	@just build-images
	@just up

# show the running containers and port mappings for the bolt devnet
inspect:
	kurtosis enclave inspect bolt-devnet

# format a rust crate. Must be run from the root of the crate's cargo directory
fmt crate:
  rustup toolchain install nightly-2024-10-03 > /dev/null 2>&1 && \
  cd $(git rev-parse --show-toplevel)/{{crate}} && \
  cargo +nightly-2024-10-03 fmt

[private]
bash service:
    @id=$(docker ps -n 100 | grep {{ service }} | awk -F' ' '{print $1}') && \
    docker exec -it $id bash

[private]
log service:
    @id=$(docker ps -n 100 | grep {{ service }} | awk -F' ' '{print $1}') && \
    docker logs -f $id

[private]
dump service:
  @id=$(docker ps -n 100 | grep {{ service }} | awk -F' ' '{print $1}') && \
  docker logs $id 2>&1 | tee {{ service }}_dump.log 

# show the logs for the bolt devnet relay
relay-logs:
    @just log helix-relay

# show the logs for the bolt devnet builder
builder-logs:
    @just log bolt-builder

# show the logs for the bolt devnet bolt-boost sidecar
boost-logs:
    @just log bolt-boost

# show the logs for the bolt devnet mev-boost sidecar
mev-boost-logs:
    @just log bolt-mev-boost

# show the logs for the bolt devnet bolt-sidecar
sidecar-logs:
    @just log sidecar

# show the logs for the bolt devnet for beacon node
beacon-logs:
    @just log 'cl-1-lighthouse-geth'

# dump the logs for the bolt devnet for beacon node to a _dump.log file
beacon-dump:
    @just dump 'cl-1-lighthouse-geth'

# dump the logs for the bolt devnet relay to a _dump.log file
relay-dump:
    @just dump mev-relay-api

# dump the logs for the bolt devnet builder to a _dump.log file
builder-dump:
    @just dump bolt-builder

# dump the logs for the bolt devnet mev-boost sidecar to a _dump.log file
boost-dump:
    @just dump bolt-mev-boost

# dump the logs for the bolt devnet bolt-sidecar to a _dump.log file
sidecar-dump:
    @just dump sidecar

# stop the bolt devnet builder container, useful for testing reliability
kill-builder:
    @id=$(docker ps -n 100 | grep bolt-builder | awk -F' ' '{print $1}') && \
    docker stop $id

# show the dora explorer in the browser. NOTE: works only for Linux and MacOS
dora:
  @url=$(just inspect | grep 'dora\s*http' | awk -F'-> ' '{print $2}' | awk '{print $1}') && \
  if [ "$(uname)" = "Darwin" ]; then \
    open "$url"; \
  else \
    xdg-open "$url"; \
  fi

# show the grafana dashboard in the browser. NOTE: works only for Linux and MacOS
grafana:
  @url=$(just inspect | grep 'grafana\s*http' | awk -F'-> ' '{print $2}' | awk '{print $1}') && \
  if [ "$(uname)" = "Darwin" ]; then \
    open "$url"; \
  else \
    xdg-open "$url"; \
  fi

# manually send a preconfirmation to the bolt devnet
send-preconf count='1':
    cd bolt-cli && RUST_LOG=info cargo run -- send \
        --devnet \
        --devnet.execution_url $(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
        --devnet.beacon_url $(kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
        --devnet.sidecar_url http://$(kurtosis port print bolt-devnet bolt-sidecar-1-lighthouse-geth api) \
        --private-key 53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710 \
        --count {{count}}

# manually send a blob preconfirmation to the bolt devnet
send-blob-preconf count='1':
    cd bolt-cli && RUST_LOG=info cargo run -- send \
        --devnet \
        --devnet.execution_url $(kurtosis port print bolt-devnet el-1-geth-lighthouse rpc) \
        --devnet.beacon_url $(kurtosis port print bolt-devnet cl-1-lighthouse-geth http) \
        --devnet.sidecar_url http://$(kurtosis port print bolt-devnet bolt-sidecar-1-lighthouse-geth api) \
        --private-key 53321db7c1e331d93a11a41d16f004d7ff63972ec8ec7c25db329728ceeb1710 \
        --blob \
        --count {{count}}

# build all the docker images locally
build-local-images:
	@just build-local-sidecar
	@just build-local-bolt-boost

# build the docker image for the bolt sidecar
[private]
build-local-sidecar:
	cd bolt-sidecar && docker build -t ghcr.io/chainbound/bolt-sidecar:0.1.0 . --load

# build the docker image for bolt-boost
[private]
build-local-bolt-boost:
	cd bolt-boost && docker build -t ghcr.io/chainbound/bolt-boost:0.1.0 . --load


# Cross platform builds
# 
# We use cargo-zigbuild to build cross-platform binaries faster and to get around
# weird linking bugs that often happen with cross or similar tools.
# 
# Steps:
# 1. install zig: 
#       ubuntu: snap install zig --classic --beta
#       macOS: brew install zig
#       others: https://github.com/ziglang/zig/wiki/Install-Zig-from-a-Package-Manager
# 2. install zigbuild: cargo install cargo-zigbuild
# 
# build the cross platform binaries for a package by name. available: "bolt-sidecar", "bolt-boost".
[private]
cross-build-binary package target_arch release_dir:
    rustup target add {{target_arch}}


    cd {{package}} && cargo zigbuild --target {{target_arch}} --profile release

    mkdir -p dist/bin/{{release_dir}}
    cp {{package}}/target/{{target_arch}}/release/{{package}} dist/bin/{{release_dir}}/{{package}}

# build and push multi-platform docker images to GHCR for a package. available: "bolt-sidecar", "bolt-boost".
build-and-push-image package tag:
    @just cross-build-binary {{package}} x86_64-unknown-linux-gnu amd64
    @just cross-build-binary {{package}} aarch64-unknown-linux-gnu arm64

    docker buildx build \
      --build-arg BINARY={{package}} \
      --file ./scripts/cross.Dockerfile \
      --platform linux/amd64,linux/arm64 \
      --tag ghcr.io/chainbound/{{package}}:{{tag}} \
      --push .

# build and push all the available packages to GHCR with the provided tag
build-and-push-all-images tag:
    @just build-and-push-image bolt-sidecar {{tag}}
    @just build-and-push-image bolt-boost {{tag}}
