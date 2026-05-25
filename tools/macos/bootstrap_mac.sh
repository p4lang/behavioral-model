#! /bin/bash

# SPDX-FileCopyrightText: 2016 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -e
set -x

# Installation helper.
brew_install() {
    echo "\nInstalling $1"
    if brew list $1 &>/dev/null; then
        echo "${1} is already installed"
    else
        brew install --ignore-dependencies $1 && echo "$1 is installed"
    fi
}

# Check if Homebrew is already installed.
if ! which brew > /dev/null 2>&1; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Check if brew shellenv command is already in zprofile.
if ! grep -q 'brew shellenv' ~/.zprofile; then
    if [[ $(uname -m) == 'arm64' ]]; then
        (echo; echo 'eval "$(/opt/homebrew/bin/brew shellenv)"') >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        (echo; echo 'eval "$(/usr/local/bin/brew shellenv)"') >> ~/.zprofile
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi

# Source zprofile.
source ~/.zprofile

HOMEBREW_PREFIX=$(brew --prefix)

# Fetch the latest formulae.
brew update

REQUIRED_PACKAGES=(
    autoconf automake cmake libtool
    boost bison pkg-config
    libevent openssl coreutils
    nanomsg thrift
    python3
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    brew_install ${package}
done

# bison needs to be on PATH before system bison.
if ! grep -q "$(brew --prefix bison)/bin" ~/.bash_profile; then
    echo 'export PATH="$(brew --prefix bison)/bin:$PATH"' >> ~/.bash_profile
fi

source ~/.bash_profile

# Install Python dependencies.
pip3 install scapy pynng==0.9.0 PyYAML
