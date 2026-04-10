#! /bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source $THIS_DIR/common.sh

check_lib libnng libnng.so.1

exit 0

set -ex
git clone https://github.com/nanomsg/nng
cd nng
git checkout v1.11

mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=ON ..
make
# Installs into /usr/local by default
sudo make install
