#!/bin/bash

function check_dependencies ()
{
    if [ ! -d /etc/cross ]; then
        echo "[Error: cross-compilers not installed]"
        exit 1
    fi

    if [ -z $(command -v elf2bin) ]; then
        echo "[Error: elf2bin is required]"
        exit 1
    fi
}

function build_target ()
{
    if [ ! -d /etc/cross/$1 ]; then
        echo "[Error: missing cross-compiler - $1]"
        return 1
    fi

    echo "[Building dependencies ($1)]"
    make TARGET=$1 &>/dev/null

    if ! [ $? -eq 0 ]; then
        echo "[Error: failed to build dependencies ($1)]"
        exit 1
    fi

    echo "[Done building dependencies ($1)]"

    echo "[Building Pwny ($1)]"
    cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/$1.cmake -DMAIN=ON -B build &>/dev/null

    if ! [ $? -eq 0 ]; then
        echo "[Error: failed to build Pwny ($1)]"
        exit 1
    fi

    cmake --build build &>/dev/null

    if ! [ $? -eq 0 ]; then
        echo "[Error: failed to build Pwny ($1)]"
        exit 1
    fi

    cp build/main pwny/templates/$1.exe
    elf2bin build/main pwny/templates/$1.bin

    echo "[Done building Pwny ($1)]"
}

function build_all ()
{
    build_target aarch64-linux-musl
    build_target armv5l-linux-musleabi
    build_target i486-linux-musl
    build_target x86_64-linux-musl
    build_target powerpc-linux-muslsf
    build_target powerpc64le-linux-musl
    build_target mips-linux-muslsf
    build_target mipsel-linux-muslsf
    build_target mips64-linux-musl
    build_target s390x-linux-musl
}

build_all
