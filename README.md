# Pwny

<p>
    <a href="https://entysec.com">
        <img src="https://img.shields.io/badge/developer-EntySec-blue.svg">
    </a>
    <a href="https://github.com/EntySec/Pwny">
        <img src="https://img.shields.io/badge/language-C-grey.svg">
    </a>
    <a href="https://github.com/EntySec/Pwny/forks">
        <img src="https://img.shields.io/github/forks/EntySec/Pwny?color=green">
    </a>
    <a href="https://github.com/EntySec/Pwny/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/Pwny?color=yellow">
    </a>
    <a href="https://www.codefactor.io/repository/github/EntySec/Pwny">
        <img src="https://www.codefactor.io/repository/github/EntySec/Pwny/badge">
    </a>
</p>

Pwny is an implementation of an advanced payload written in pure C and designed for portability and extensibility.

That repository contains Pwny, which is supposed to work on `macOS`, `Linux`, `Windows` and `Apple iOS`, but can be ported to almost every Posix system. Note that `Android` app will come soon with generic support of this native Pwny codebase and will be optimized to work with HatSploit Framework as well as with Ghost Framework.

## Features

* Portable C code, that can be compiled for a big range of CPUs.
* Support for `macOS`, `Linux`, `Windows` and `Apple iOS` targets.
* Small executable with low resource utilization which is good on embedded systems.
* Dynamically-extendable, might load plugins which will extend its functions.
* Evasion techniques such as process migration.

## Installing

You should install HatSploit to get Pwny, because Pwny depends on HatSploit Framework.

```
pip3 install git+https://github.com/EntySec/HatSploit
```

## Building Pwny

These are platforms which are supported by Pwny.

First, you need to build dependencies for your platform, so do this:

```shell
cd make
make PLATFORM=<platform> ARCH=<arch>
```

Then you need to execute these commands to build Pwny executable:

```shell
cmake -DCMAKE_TOOLCHAIN_PATH=<toolchain> -B build
cmake --build build
```

There are some `cmake` build options that allows you to build for the specific platform.

* `IPHONE` - Should be `ON` if building for Apple iOS.
* `SDK` - Set SDK for macOS and Apple iOS targets.
  * macOS patched SDKs from [here](https://github.com/phracker/MacOSX-SDKs).
  * Apple iOS patched SDKs from [here](https://github.com/theos/sdks).
* `DEBUG` - Enable debug logging for development.

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny.session import PwnySession
```

* `Pwny` - Pwny utilities, mostly for generating payloads and encoding arguments.
* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload.

## Caveats

The code provided in this repository has not yet been prepared for use in a production environment. It can be improved anyways, so any contribution is welcome. Unfortunately, most part of the codebase is unstable due to the lack of testing. You can even experience memory leaks, so we'll be glad to accept every single PR which is fixing a potential issue.
