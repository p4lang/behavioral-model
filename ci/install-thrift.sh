#!/bin/sh

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source $THIS_DIR/common.sh

check_lib libthrift libthrift-0.16.0

set -e
git clone -b 0.16.0 https://github.com/apache/thrift.git thrift-0.16.0
cd thrift-0.16.0
./bootstrap.sh
./configure --with-as3=no --with-c_glib=no --with-csharp=no --with-cpp=yes \
    --with-cl=no --with-d=no --with-dart=no --with-dotnetcore=no \
    --with-erlang=no --with-go=no --with-haskell=no --with-haxe=no \
    --with-java=no --with-lua=no --with-nodejs=no --with-nodets=no \
    --with-perl=no --with-php=no --with-python=no --with-py3=no \
    --with-qt5=no --with-ruby=no --with-rs=no --with-swift=no
make -j4 && sudo make install
cd ..
pip install thrift==0.16.0
