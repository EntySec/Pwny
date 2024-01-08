# Pwny

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-C-grey.svg)](https://github.com/EntySec/Pwny)
[![Language](https://img.shields.io/badge/language-Python-blue.svg)](https://github.com/EntySec/Pwny)
[![Forks](https://img.shields.io/github/forks/EntySec/Pwny?style=flat&color=green)](https://github.com/EntySec/Pwny/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/Pwny?style=flat&color=yellow)](https://github.com/EntySec/Pwny/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/Pwny/badge)](https://www.codefactor.io/repository/github/EntySec/Pwny)

Pwny is an implementation of an advanced payload written in pure C and designed for portability and extensibility.

That repository contains Pwny, which is supposed to work on `macOS`, `Linux`, `Windows` and `iOS`, but can be ported to almost every Posix system. Pwny is optimized to work with or without [HatSploit Framework](https://github.com/EntySec/HatSploit).

## Features

* Portable C code, that can be compiled for a big range of CPUs and platforms.
* Support for `macOS`, `Linux`, `Windows` and `iOS` targets.
* Small executable with low resource utilization which is good on embedded systems.
* Dynamically-extendable, might load plugins which will extend its functions.
* Evasion techniques such as process migration and in-memory loading.

## Installing

To install Pwny you simply need to install [HatSploit Framework](https://github.com/EntySec/HatSploit) and this will make Pwny available automatically.

```
pip3 install git+https://github.com/EntySec/HatSploit
```

## Building Pwny

First, you need to build dependencies for your platform, so do this:

```shell
cd make
make PLATFORM=<platform> ARCH=<arch> MAKE_TOOLCHAIN_FILE=<toolchain>
```

For `macOS` and `iOS` targets you will need to set `SDK` to the desired SDK path before running `make`. For example:

```shell
export SDK=<path>
```

**NOTE:** Make toolchains are located at `toolchain/make/`.

Then you need to execute these commands to build Pwny executable:

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=<toolchain> -B build
cmake --build build
```

For `macOS` and `iOS` targets you will need to set `CMAKE_OSX_SYSROOT` to the desired SDK path with `-D`. For example:

```shell
cmake -DCMAKE_TOOLCHAIN_FILE=<toolchain> -DCMAKE_OSX_SYSROOT=<path> -B build
```

**NOTE:** CMake toolchains are located at `toolchain/cmake/`.

These are other `cmake` build options:

* `MAIN` - Should be `ON` if you want to build a source file to executable.
* `SOURCE` - Custom executable source file (default are in `src/main/`).
* `DEBUG` - Should be `ON` if you want to build Pwny in debug mode.

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny import Pwny
from pwny.session import PwnySession
```

* `Pwny` - Pwny utilities, mostly for generating payloads.
* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload.

## Executing Pwny

Pwny is an advanced payload that may be loaded in-memory, so all you need to do is to build Pwny, place the DLL (for Windows) or executable (for other OS) to `pwny/templates/<platform>/<arch>.bin` and then generate the loader from `payloads/`. After this, all you need to do is to set up the listener on attacker's machine and execute the generated loader on the target.

You can find examples of listeners at `examples/`.

**NOTE:** To generate loader, you should use [`hsfgen`](https://docs.hatsploit.com/docs/getting-started/using-hsfgen), just make sure that payload is either `<platform>/<arch>/pwny_reverse_tcp` or `<platform>/<arch>/pwny_bind_tcp`. 

## Testing Pwny

To test Pwny, simply compile `src/main/test.c` (do not forget to change host and port in it) and then execute `examples/listener.py` on attacker and compiled Pwny on target with command-line arguments like `<host> <port>`.

**NOTE:** No loader is needed for testing, do not overcomplicate it! To disable in-memory loading add `loader=False` to `open()` in `examples/listener.py`.

## Projects

* [SeaShell Framework](https://github.com/EntySec/SeaShell) - iOS post-exploitation framework that exploits the CoreTrust bug to remotely access an iPhone or iPad. SeaShell actively using Pwny implant to communicate with iOS.

## Caveats

The code provided in this repository has not yet been prepared for use in a production environment. It can be improved, so any contribution is welcome. You can even experience memory leaks, so we'll be glad to accept every single PR which is fixing a potential issue.
