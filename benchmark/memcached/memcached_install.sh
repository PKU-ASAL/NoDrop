#!/bin/bash

set -x

tar -xzvf memcached-1.6.9.tar.gz
tar -xzvf mcperf-0.1.1.tar.gz

mv memcached-1.6.9 memcached_
mv mcperf-0.1.1 mcperf_

cd memcached_
./configure
make

cd ../mcperf_
./configure
make

