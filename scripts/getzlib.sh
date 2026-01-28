#!/bin/bash
set -e

BASE_DIR="$(cd "$(dirname "$0")/.."; pwd)"

ZLIB_VERSION="1.3.1"
ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"

ZLIB_TAR="${BASE_DIR}/zlib-${ZLIB_VERSION}.tar.gz"
ZLIB_TMP_DIR="${BASE_DIR}/zlib-${ZLIB_VERSION}"
ZLIB_DST_DIR="${BASE_DIR}/zlib"

echo "[1] Download zlib ${ZLIB_VERSION}"
cd "$BASE_DIR"

rm -rf "$ZLIB_TAR" "$ZLIB_TMP_DIR"
wget "$ZLIB_URL" -O "$ZLIB_TAR"

tar xf "$ZLIB_TAR"

echo "[2] Move zlib sources"

rm -rf "$ZLIB_DST_DIR"
mv "$ZLIB_TMP_DIR" "$ZLIB_DST_DIR"

rm -rf "$ZLIB_TAR"

echo "[✓] zlib source is ready at ${ZLIB_DST_DIR}"
