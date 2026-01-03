#!/bin/bash
set -e

BASE_DIR="$(cd "$(dirname "$0")/.."; pwd)"

LUA_URL="https://www.lua.org/ftp/lua-5.4.6.tar.gz"
LUA_TAR="${BASE_DIR}/lua-5.4.6.tar.gz"
LUA_TMP_DIR="${BASE_DIR}/lua-5.4.6"
LUA_DST_DIR="${BASE_DIR}/lua"

echo "[1] Download Lua 5.4.6"
cd "$BASE_DIR"

rm -rf "$LUA_TAR" "$LUA_TMP_DIR"
wget "$LUA_URL" -O "$LUA_TAR"

tar xf "$LUA_TAR" -C "$BASE_DIR"

rm -rf "$LUA_DST_DIR"
mv "$LUA_TMP_DIR/src" "$LUA_DST_DIR"

rm -rf "$LUA_TMP_DIR" "$LUA_TAR"

echo "[2] disable package library in lua/linit.c"

LUA_LINIT_FILE="${LUA_DST_DIR}/linit.c"

sed -i 's/^\([[:space:]]*{\s*LUA_LOADLIBNAME\s*,\s*luaopen_package\s*}\s*,\)/\/\/ \1/' "$LUA_LINIT_FILE"
