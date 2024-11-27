#!/usr/bin/env bash
set -eo pipefail

# 'boltup' installation script.
#
# This script is a carbon copy of 'foundryup' (https://github.com/foundry-rs/foundry/blob/master/foundryup/README.md)
# since it is a great way to install CLI tools. The only difference is the URL and the binary name.

echo "Installing boltup..."

BASE_DIR="${XDG_CONFIG_HOME:-$HOME}"
BOLT_DIR="${BOLT_DIR:-"$BASE_DIR/.bolt"}"
BOLT_BIN_DIR="$BOLT_DIR/bin"

DEFAULT_BRANCH="unstable"
BIN_URL="https://raw.githubusercontent.com/chainbound/bolt/$DEFAULT_BRANCH/boltup/boltup.sh"
BIN_PATH="$BOLT_BIN_DIR/boltup"

# Create the .bolt bin directory and boltup binary if it doesn't exist.
mkdir -p "$BOLT_BIN_DIR"
curl -sSf -L "$BIN_URL" -o "$BIN_PATH"
chmod +x "$BIN_PATH"

# Store the correct profile file (i.e. .profile for bash or .zshenv for ZSH).
case $SHELL in
*/zsh)
    PROFILE="${ZDOTDIR-"$HOME"}/.zshenv"
    PREF_SHELL=zsh
    ;;
*/bash)
    PROFILE=$HOME/.bashrc
    PREF_SHELL=bash
    ;;
*/fish)
    PROFILE=$HOME/.config/fish/config.fish
    PREF_SHELL=fish
    ;;
*/ash)
    PROFILE=$HOME/.profile
    PREF_SHELL=ash
    ;;
*)
    echo "boltup: could not detect shell, manually add ${BOLT_BIN_DIR} to your PATH."
    exit 1
    ;;
esac

# Only add boltup if it isn't already in PATH.
if [[ ":$PATH:" != *":${BOLT_BIN_DIR}:"* ]]; then
    # Add the boltup directory to the path and ensure the old PATH variables remain.
    # If the shell is fish, echo fish_add_path instead of export.
    if [[ "$PREF_SHELL" == "fish" ]]; then
        echo >>"$PROFILE" && echo "fish_add_path -a $BOLT_BIN_DIR" >>"$PROFILE"
    else
        echo >>"$PROFILE" && echo "export PATH=\"\$PATH:$BOLT_BIN_DIR\"" >>"$PROFILE"
    fi
fi

# Warn MacOS users that they may need to manually install libusb via Homebrew:
if [[ "$OSTYPE" =~ ^darwin ]] && [[ ! -f /usr/local/opt/libusb/lib/libusb-1.0.0.dylib && ! -f /opt/homebrew/opt/libusb/lib/libusb-1.0.0.dylib ]]; then
    echo && echo "warning: libusb not found. You may need to install it manually on MacOS via Homebrew (brew install libusb)."
fi

echo
echo "Detected your preferred shell is $PREF_SHELL and added boltup to PATH."
echo "Run 'source $PROFILE' or start a new terminal session to use boltup."
echo "Then, simply run 'boltup' to install the bolt CLI."
