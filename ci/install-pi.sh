#!/bin/sh
set -e

git clone --depth 1 https://github.com/p4lang/PI.git
cd PI
git submodule update --init --recursive

./autogen.sh
./configure --with-proto --without-internal-rpc --without-cli --without-bmv2
make -j"$(nproc)"
sudo make install
