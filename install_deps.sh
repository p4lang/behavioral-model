#!/bin/bash
set -e
if [ ! -r /etc/os-release ]
then
    1>&2 echo "No file /etc/os-release.  Cannot determine what OS this is."
    exit 1
fi
source /etc/os-release

if [ "${ID}" = "ubuntu" ]
then
    sudo apt-get install -y \
         automake \
         cmake \
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
         libssl-dev \
         libffi-dev \
         python3-dev \
         python3-pip \
         wget
elif [ "${ID}" = "fedora" ]
then
    sudo dnf install -y \
         automake \
         cmake \
         gmp-devel \
         libpcap-devel \
         boost-devel \
         boost-system \
         boost-thread \
         boost-filesystem \
         boost-test \
         boost-static \
         libevent-devel \
         libtool \
         flex \
         bison \
         pkg-config \
         g++ \
         openssl-devel
fi

tmpdir=`mktemp -d -p .`
cd $tmpdir

bash ../ci/install-thrift.sh
bash ../ci/install-nanomsg.sh
sudo ldconfig
bash ../ci/install-nnpy.sh

cd ..
sudo rm -rf $tmpdir
