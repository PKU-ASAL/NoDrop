#!/bin/sh

NRCPUS=`nproc`
mkdir nginx_

tar -xf http-test-files-1.tar.xz
tar -xf nginx-1.21.1.tar.gz

cd nginx-1.21.1/
CFLAGS="-Wno-error -O3 -march=native $CFLAGS" CXXFLAGS="-Wno-error -O3 -march=native $CFLAGS" ./configure --prefix=../nginx_ --without-http_rewrite_module --without-http-cache 
make -j $NRCPUS
make install
cd ..

sed -i "s/worker_processes  1;/worker_processes  $((NRCPUS / 2));/g" nginx_/conf/nginx.conf
sed -i "s/        listen       80;/        listen       8089;/g" nginx_/conf/nginx.conf

mv -f http-test-files/* nginx_/html/

rm -rf http-test-files
rm -rf nginx-1.21.1/