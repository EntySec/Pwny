#!/bin/bash

cd deps

echo "[Building elf2bin]"

gcc -o elf2bin elf2bin.c
cp elf2bin ../

echo "[Done building elf2bin]"

echo "[Installing kubo/injector]"

git clone https://github.com/enty8080/injector
cd injector
cmake -B build
cp src/$1/libinjector.a ../../

echo "[Done installing kubo/injector]"
