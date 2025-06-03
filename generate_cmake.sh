#!/usr/bin/bash

TARGET=build
if [[ ! -d "$TARGET" ]]; then
  mkdir -p $TARGET
fi

cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DPKEY_SUPPORT=OFF \
  -B ${TARGET} \
  -S /home/hrz/source/audit/nodrop/
