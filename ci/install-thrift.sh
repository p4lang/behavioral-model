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
./bootstrap.sh
./configure --with-as3=no --with-c_glib=no --with-csharp=no --with-cpp=yes \
    --with-cl=no --with-d=no --with-dart=no --with-dotnetcore=no \
    --with-erlang=no --with-go=no --with-haskell=no --with-haxe=no \
    --with-java=no --with-lua=no --with-nodejs=no --with-nodets=no \
    --with-perl=no --with-php=no --with-python=yes --with-py3=no \
    --with-qt5=no --with-ruby=no --with-rs=no --with-swift=no
make -j2 && sudo make install
cd lib/py
sudo python3 setup.py install
cd ../../..
