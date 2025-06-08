#!/bin/sh

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source $THIS_DIR/common.sh

check_lib libthrift libthrift-0.13.0

set -e
# Make it possible to get thrift in China
# wget http://archive.apache.org/dist/thrift/0.13.0/thrift-0.13.0.tar.gz
# tar -xzvf thrift-0.13.0.tar.gz
git clone -b 0.13.0 https://github.com/apache/thrift.git thrift-0.13.0
cd thrift-0.13.0
mkdir -p build  # Likely already exists
cd build
cmake -DWITH_AS3=OFF -DWITH_C_GLIB=OFF -DWITH_CPP=ON -DWITH_JAVA=OFF \
    -DWITH_JAVA=OFF -DWITH_PYTHON=ON -DWITH_HASKELL=OFF \
    -DCMAKE_CXX_STANDARD=17 ..
make -j4 && sudo make install
cd ..
cd lib/py
sudo python3 setup.py install
cd ../../..
