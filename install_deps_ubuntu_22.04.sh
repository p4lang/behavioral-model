#!/bin/bash
set -e

apt-get update
apt-get install -y curl gnupg
# Add repository as trusted to bypass expired GPG keys from openSUSE build service
echo 'deb [trusted=yes] http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/home:p4lang.list

apt-get update

apt-get install -qq --no-install-recommends \
    automake \
    build-essential \
    cmake \
    git \
    g++ \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libgmp-dev \
    libgrpc++-dev \
    libgrpc-dev \
    libopenmpi-dev \
    libnanomsg-dev \
    libpcap-dev \
    libprotobuf-dev \
    libprotoc-dev \
    libssl-dev \
    libthrift-0.16.0 \
    libthrift-dev \
    libtool \
    pkg-config \
    protobuf-compiler \
    protobuf-compiler-grpc \
    python3-all \
    python3-six \
    python3-thrift \
    thrift-compiler \
    libreadline-dev \
    p4lang-pi

ldconfig

python3 -m pip install --upgrade pynng==0.9.0
