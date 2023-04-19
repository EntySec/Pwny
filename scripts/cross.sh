#!/bin/bash

mkdir -p cross
cd cross

echo "[Downloading compilers]"

wget https://musl.cc/aarch64-linux-musl-cross.tgz
wget https://musl.cc/armv5l-linux-musleabi-cross.tgz
wget https://musl.cc/i486-linux-musl-cross.tgz
wget https://musl.cc/x86_64-linux-musl-cross.tgz
wget https://musl.cc/powerpc-linux-muslsf-cross.tgz
wget https://musl.cc/powerpc64le-linux-musl-cross.tgz
wget https://musl.cc/mips-linux-muslsf-cross.tgz
wget https://musl.cc/mipsel-linux-muslsf-cross.tgz
wget https://musl.cc/mips64-linux-musl-cross.tgz
wget https://musl.cc/s390x-linux-musl-cross.tgz

echo "[Done installing compilers]"

echo "[Parsing compilers]"

tar -xvzf aarch64-linux-musl-cross.tgz
tar -xvzf armv5l-linux-musleabi-cross.tgz
tar -xvzf i486-linux-musl-cross.tgz
tar -xvzf x86_64-linux-musl-cross.tgz
tar -xvzf powerpc-linux-muslsf-cross.tgz
tar -xvzf powerpc64le-linux-musl-cross.tgz
tar -xvzf mips-linux-muslsf-cross.tgz
tar -xvzf mipsel-linux-muslsf-cross.tgz
tar -xvzf mips64-linux-musl-cross.tgz
tar -xvzf s390x-linux-musl-cross.tgz

echo "[Done parsing compilers]"

echo "[Processing compilers]"

rm -rf *.tgz
mv aarch64-linux-musl-cross aarch64
mv armv5l-linux-musleabi-cross armv5l
mv i486-linux-musl-cross i486
mv x86_64-linux-musl-cross x86_64
mv powerpc-linux-muslsf-cross powerpc
mv powerpc64le-linux-musl-cross powerpc64le
mv mips-linux-muslsf-cross mips
mv mipsel-linux-muslsf-cross mipsel
mv mips64-linux-musl-cross mips64
mv s390x-linux-musl-cross s390x

echo "[Done processing compilers]"
