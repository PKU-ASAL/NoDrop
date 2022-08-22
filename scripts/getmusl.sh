#!/bin/sh

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

cd ${ROOT}/musl-src
CFLAGS="-fPIE" ./configure --prefix=${ROOT}/musl --disable-shared --enable-optimize --disable-wrapper
make -j`nproc`
make install
cd -

incdir=${ROOT}/musl/include
libdir=${ROOT}/musl/lib
ldso=/lib/ld-musl-x86_64.so.1

cat > ${ROOT}/monitor/musl.specs << EOF
%rename cpp_options old_cpp_options

*cpp_options:
-nostdinc -isystem $incdir -isystem include%s %(old_cpp_options)

*cc1:
%(cc1_cpu) -nostdinc -isystem $incdir -isystem include%s

*link_libgcc:
-L$libdir -L .%s

*libgcc:
libgcc.a%s %:if-exists(libgcc_eh.a%s)

*startfile:
%{shared:;static:$libdir/crt1.o%s; static-pie:$libdir/rcrt1.o%s; pie:$libdir/Scrt1.o%s; :$libdir/crt1.o%s} $libdir/crti.o%s %{static:crtbeginT.o%s; shared|static-pie|pie:crtbeginS.o%s; :crtbegin.o%s}

*endfile:
%{static:crtend.o%s; shared|static-pie|pie:crtendS.o%s; :crtend.o%s} $libdir/crtn.o%s

*link:
%{!r:--build-id} --no-add-needed %{!static|static-pie:--eh-frame-hdr} --hash-style=gnu %{shared:-shared} %{!shared:%{!static:%{!static-pie:%{rdynamic:-export-dynamic} -dynamic-linker $ldso}} %{static:-static} %{static-pie:-static -pie --no-dynamic-linker -z text}}

*esp_link:


*esp_options:


*esp_cpp_options:


EOF

rm -rf ${ROOT}/musl-src
rm ${MUSL}-${VERSION}.tar.gz
