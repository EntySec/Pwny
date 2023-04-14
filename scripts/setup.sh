#!/bin/bash

export CC=$2
export AR=$3

cd deps

echo "[Installing kubo/injector]"

git clone https://github.com/enty8080/injector
cd injector
make $1
cp src/$1/libinjector.a ../../

echo "[Done installing kubo/injector]"
