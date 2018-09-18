#!/bin/sh
set -e
# Check whether running Ubuntu >= 18.04
if test `lsb_release -rs` = '18.04';
then
    echo "Detected Ubuntu 18.04, using libssl1.0-dev"
    LIBSSL="libssl1.0-dev"
else
    LIBSSL="libssl-dev"
fi
sudo apt-get install -y \
    automake \
    cmake \
    libjudy-dev \
    libgmp-dev \
    libpcap-dev \
    libboost-dev \
    libboost-test-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-thread-dev \
    libevent-dev \
    libtool \
    flex \
    bison \
    pkg-config \
    g++ \
    $LIBSSL \
    libffi-dev \
    python-dev \
    python-pip \
    wget

tmpdir=`mktemp -d -p .`
cd $tmpdir

bash ../travis/install-thrift.sh
bash ../travis/install-nanomsg.sh
sudo ldconfig
bash ../travis/install-nnpy.sh

cd ..
sudo rm -rf $tmpdir
