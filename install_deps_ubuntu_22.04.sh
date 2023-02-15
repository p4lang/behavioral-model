#!/bin/bash
set -e

apt-get update
apt-get install -y curl gnupg
echo 'deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_22.04/ /' | tee /etc/apt/sources.list.d/home:p4lang.list
curl -fsSL https://download.opensuse.org/repositories/home:p4lang/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null

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
