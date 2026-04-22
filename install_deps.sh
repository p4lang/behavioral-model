#!/bin/bash

# SPDX-FileCopyrightText: 2015 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

set -e

sudo apt-get install -y \
    autoconf \
    automake \
    bison \
    build-essential \
    ccache \
    cmake \
    flex \
    git \
    g++ \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libevent-dev \
    libffi-dev \
    libgmp-dev \
    libgrpc++-dev \
    libgrpc-dev \
    libnanomsg-dev \
    libpcap-dev \
    libprotobuf-dev \
    libprotoc-dev \
    libreadline-dev \
    libssl-dev \
    libthrift-dev \
    libtool \
    libtool-bin \
    pkg-config \
    protobuf-compiler \
    protobuf-compiler-grpc \
    python3-dev \
    python3-pip \
    python3-six \
    python3-thrift \
    thrift-compiler \
    wget

tmpdir=`mktemp -d -p .`
cd $tmpdir

bash ../ci/install-thrift.sh
bash ../ci/install-nanomsg.sh
bash ../ci/install-pi.sh
sudo ldconfig
bash ../ci/install-pynng.sh

cd ..
sudo rm -rf $tmpdir
