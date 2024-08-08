#!/bin/bash

if [ -z $(command -v git) ]; then
    echo "[Error: elf2bin is required]"
    exit 1
fi

echo "[Building dependencies (aarch64)]"
make TARGET=aarch64-linux-musl &>/dev/null

if ! [ $? -eq 0 ]; then
    echo "[Error: failed to build dependencies (aarch64)]"
    exit 1
fi

echo "[Done building dependencies (aarch64)]"

echo "[Building Pwny (aarch64)]"
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-linux-musl.cmake -DMAIN=ON -B build &>/dev/null

if ! [ $? -eq 0 ]; then
    echo "[Error: failed to build Pwny (aarch64)]"
    exit 1
fi

cmake --build build &>/dev/null

if ! [ $? -eq 0 ]; then
    echo "[Error: failed to build Pwny (aarch64)]"
    exit 1
fi

echo "[Done building Pwny (aarch64)]"
