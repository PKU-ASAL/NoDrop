#!/bin/sh

tar -xzf redis-6.0.9.tar.gz
mv -f redis-6.0.9 redis_
NOW=`pwd`

cd $NOW/redis_/deps
make hiredis jemalloc linenoise lua

cd $NOW/redis_
make MALLOC=libc -j `nproc`