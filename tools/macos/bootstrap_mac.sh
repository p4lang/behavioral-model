#! /bin/bash
# SPDX-FileCopyrightText: 2016 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -x

# Installation helper: skip already-installed packages.
brew_install() {
    if brew list "$1" &>/dev/null; then
        echo "$1 is already installed, skipping"
    else
        brew install "$1"
    fi
}

# Check if Homebrew is already installed.
if ! command -v brew &>/dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Add Homebrew to PATH for both arm64 (Apple Silicon) and x86_64.
if [[ $(uname -m) == 'arm64' ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
else
    eval "$(/usr/local/bin/brew shellenv)"
fi

# Fetch the latest formulae.
brew update

# Required packages for bmv2.
REQUIRED_PACKAGES=(
    autoconf
    automake
    cmake
    libtool
    boost
    bison
    pkg-config
    libevent
    openssl
    coreutils
    gmp
    nanomsg
    thrift
    xxhash
    jsoncpp
    python3
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    brew_install "${package}"
done

# bison installed via Homebrew must appear before system bison on PATH.
export PATH="$(brew --prefix bison)/bin:$PATH"

# Install Python dependencies.
# --break-system-packages is required on modern macOS (PEP 668) to allow
# pip to install into the system Python environment.
pip3 install --user --break-system-packages scapy pynng==0.9.0 PyYAML
