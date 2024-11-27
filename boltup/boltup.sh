#!/usr/bin/env bash
set -eo pipefail

# 'boltup' script for installing and managing the bolt CLI tool.
#
# This script is a heavily inspired by 'foundryup' (https://github.com/foundry-rs/foundry/blob/master/foundryup/foundryup)
# since it is a great way to install CLI tools. Kudos to the Foundry team :)

BASE_DIR=${XDG_CONFIG_HOME:-$HOME}
BOLT_DIR=${BOLT_DIR:-"$BASE_DIR/.bolt"}
BOLT_BIN_DIR="$BOLT_DIR/bin"

main() {
  need_cmd git
  need_cmd curl

  # Loop as long as $1 (the first positional argument) is not empty, and match its 
  # value against existing flags. If a flag is found, the argument is discarded 
  # (via shift) and the value for the flag is read.
  while [[ -n $1 ]]; do
    case $1 in
      --)               shift; break;;

      -t|--tag)     shift; BOLTUP_TAG=$1;;
      --arch)       shift; BOLTUP_ARCH=$1;;
      --platform)   shift; BOLTUP_PLATFORM=$1;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        warn "unknown option: $1"
        usage
        exit 1
    esac; shift
  done

  # Print the banner after successfully parsing args
  banner

  BOLTUP_REPO="chainbound/bolt"

  # Install by downloading binaries (default: "latest" tag)
  BOLTUP_TAG=${BOLTUP_TAG:-latest}

  # Normalize versions (handle channels, versions without v prefix
  if [[ "$BOLTUP_TAG" == [[:digit:]]* ]]; then
    # Add v prefix
    BOLTUP_TAG="v${BOLTUP_TAG}"
  fi

  say "installing bolt (tag ${BOLTUP_TAG})"

  # Figure out the platform: one of "linux", "darwin" or "win32"
  uname_s=$(uname -s)
  PLATFORM=$(tolower "${BOLTUP_PLATFORM:-$uname_s}")
  EXT="tar.gz"
  case $PLATFORM in
  linux) ;;
  darwin | mac*)
    PLATFORM="darwin"
    ;;
  mingw* | win*)
    # revert, as Windows is not supported currently
    # TODO: add Windows binaries and support
    err "Windows is not supported yet!"

    EXT="zip"
    PLATFORM="win32"
    ;;
  *)
    err "unsupported platform: $PLATFORM"
    ;;
  esac

  # Figure out the architecture: one of "amd64" or "arm64"
  uname_m=$(uname -m)
  ARCHITECTURE=$(tolower "${BOLTUP_ARCH:-$uname_m}")
  if [ "${ARCHITECTURE}" = "x86_64" ]; then
    # Redirect stderr to /dev/null to avoid printing errors if non Rosetta.
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
      ARCHITECTURE="arm64" # Rosetta.
    else
      ARCHITECTURE="amd64" # Intel.
    fi
  elif [ "${ARCHITECTURE}" = "arm64" ] || [ "${ARCHITECTURE}" = "aarch64" ]; then
    ARCHITECTURE="arm64" # Arm.
  else
    ARCHITECTURE="amd64" # Amd.
  fi

  # Compute the URL of the release tarball in the Bolt repository.
  RELEASE_URL="https://github.com/${BOLTUP_REPO}/releases/download/${BOLTUP_TAG}/"
  # Examples: "bolt-cli-amd64-darwin.tar.gz" or "bolt-cli-arm64-linux.tar.gz"
  BIN_FILENAME="bolt-cli-${ARCHITECTURE}-${PLATFORM}.$EXT"
  BIN_ARCHIVE_URL="${RELEASE_URL}${BIN_FILENAME}"

  # Download and extract the binaries archive
  say "downloading latest binary"
  if [ "$PLATFORM" = "win32" ]; then
    tmp="$(mktemp -d 2>/dev/null || echo ".")/bolt.zip"
    ensure download "$BIN_ARCHIVE_URL" "$tmp"
    ensure unzip "$tmp" -d "$BOLT_BIN_DIR"
    rm -f "$tmp"
  else
    ensure download "$BIN_ARCHIVE_URL" | ensure tar -xzC "$BOLT_BIN_DIR"
  fi

  bin_path="$BOLT_BIN_DIR/bolt"

  # Print installed msg
  say "installed - $(ensure "$bin_path" --version)"

  # Check if the default path of the binary is not in BOLT_BIN_DIR
  which_path="$(command -v "$bin" || true)"
  if [ -n "$which_path" ] && [ "$which_path" != "$bin_path" ]; then
    warn ""
    cat 1>&2 <<EOF
There are multiple binaries with the name 'bolt' present in your 'PATH'.
This may be the result of installing 'bolt' using another method,
like Cargo or other package managers.
You may need to run 'rm $which_path' or move '$BOLT_BIN_DIR'
in your 'PATH' to allow the newly installed version to take precedence!

EOF
  fi

  say "done!"
}

usage() {
  cat 1>&2 <<EOF
The installer for bolt CLI.

Update or revert to a specific bolt version with ease.

By default, the latest unstable version is installed from built binaries.

USAGE:
    boltup <OPTIONS>

OPTIONS:
    -h, --help      Print help information
    -t, --tag       Install a specific version from built binaries (default: latest)
    --arch          Install a specific architecture (supports amd64 and arm64)
    --platform      Install a specific platform (supports linux, and darwin)
EOF
}

say() {
  printf "boltup: %s\n" "$1"
}

warn() {
  say "warning: ${1}" >&2
}

err() {
  say "$1" >&2
  exit 1
}

tolower() {
  echo "$1" | awk '{print tolower($0)}'
}

need_cmd() {
  if ! check_cmd "$1"; then
    err "need '$1' (command not found)"
  fi
}

check_cmd() {
  command -v "$1" &>/dev/null
}

# Run a command that should never fail. If the command fails execution
# will immediately terminate with an error showing the failing command.
ensure() {
  if ! "$@"; then err "command failed: $*"; fi
}

# Downloads $1 into $2 or stdout
download() {
  if [ -n "$2" ]; then
    # output into $2
    if check_cmd curl; then
      curl -#o "$2" -L "$1"
    else
      wget --show-progress -qO "$2" "$1"
    fi
  else
    # output to stdout
    if check_cmd curl; then
      curl -#L "$1"
    else
      wget --show-progress -qO- "$1"
    fi
  fi
}

# Banner Function for Bolt
banner() {
  printf '

.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx

        Bolt: Permissionless proposr commitments on Ethereum.

.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx.xOx

'
}

main "$@"
