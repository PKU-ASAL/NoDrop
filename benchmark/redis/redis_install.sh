#!/bin/sh

set -x
NOW=`pwd`

tar -xzf redis-6.0.9.tar.gz
mv -f redis-6.0.9 redis_

cd $NOW/redis_/deps
make hiredis jemalloc linenoise lua

cd $NOW/redis_
make MALLOC=libc -j `nproc`

tar -xzf memtier_benchmark-1.3.0.tar.gz
mv -f memtier_benchmark-1.3.0 memtier_

cd $NOW/memtier_
echo "Installing dependencies. Root privilege required"
sudo apt-get install build-essential autoconf automake libpcre3-dev libevent-dev pkg-config zlib1g-dev libssl-dev -y

autoreconf -ivf
./configure
make
