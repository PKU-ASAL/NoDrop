#!/bin/sh

NRCPUS=`nproc`
INSTALL_DIR=`pwd`/nginx_
mkdir $INSTALL_DIR

tar -xf http-test-files-1.tar.xz
tar -xf nginx-1.21.1.tar.gz

cd nginx-1.21.1/
CFLAGS="-Wno-error -O3 -march=native $CFLAGS" CXXFLAGS="-Wno-error -O3 -march=native $CFLAGS" ./configure --prefix=$INSTALL_DIR --without-http_rewrite_module --without-http-cache 
make -j $NRCPUS
make install
cd ..

sed -i "s/        listen       80;/        listen       8089;/g" nginx_/conf/nginx.conf

mv -f http-test-files/* nginx_/html/

rm -rf http-test-files
rm -rf nginx-1.21.1/

unzip wrk.zip
mv wrk-master/ wrk_/
cd wrk_/
make
