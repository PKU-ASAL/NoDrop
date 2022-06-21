#/bin/sh

if [ $# -lt 1 ] || [[ "$1" != /* ]]; then 
    echo "Usage: $0 <absolute-path-to-NoDrop>"
    exit 1
fi

set -e

MUSL=musl
VERSION=1.2.3
ROOT=$1

wget --no-check-certificate https://musl.libc.org/releases/${MUSL}-${VERSION}.tar.gz
tar xf ${MUSL}-${VERSION}.tar.gz

mv ${MUSL}-${VERSION} ${ROOT}/musl-src
mkdir -p ${ROOT}/musl

cd ${ROOT}/musl-src && ./configure --prefix=${ROOT}/musl --disable-shared --enable-optimize --disable-wrapper && cd -
make -C ${ROOT}/musl-src -j`nproc`
make -C ${ROOT}/musl-src install

cat > ${ROOT}/monitor/musl.specs << EOF
%rename cpp_options old_cpp_options

*cpp_options:
-nostdinc -isystem ${ROOT}/musl/include -isystem include%s %(old_cpp_options)

*cc1:
%(cc1_cpu) -nostdinc -isystem ${ROOT}/musl/include -isystem include%s

*link_libgcc:
-L${ROOT}/musl/lib -L .%s

*libgcc:
libgcc.a%s %:if-exists(libgcc_eh.a%s)

*startfile:
%{static-pie: rcrt1.o} %{!static-pie: %{!shared: ${ROOT}/musl/lib/Scrt1.o}} ${ROOT}/musl/lib/crti.o crtbeginS.o%s

*endfile:
crtendS.o%s ${ROOT}/musl/lib/crtn.o

*link:
%{static-pie:-no-dynamic-linker -static} %{!static-pie:-dynamic-linker /lib/ld-musl-x86_64.so.1} -nostdlib %{shared:-shared} %{static:-static} %{rdynamic:-export-dynamic}

*esp_link:


*esp_options:


*esp_cpp_options:


EOF

rm -rf ${ROOT}/musl-src
rm ${MUSL}-${VERSION}.tar.gz
