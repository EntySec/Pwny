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

Pwny is an implementation of an advanced native-code payload written in pure C and designed for portability, embeddability, and extensibility.

That repository contains Pwny, which is supposed to work on `macOS`, `Linux`, `Windows` and `Apple iOS`, but can be ported to almost every Posix system. Note that `Android` app will come soon with generic support of this native Pwny codebase and will be optimized to work with HatSploit Framework (Checkmate C2) as well as with Ghost Framework.

## Features

* Portable C code, that can be compiled for a big range of CPUs.
* Support for `macOS`, `Linux`, `Windows` and `Apple iOS` targets.
* Small executable with low resource utilization which is good on embedded systems.
* Dynamically-extendable, might load plugins which are shared libraries.
* Evasion techniques such as process migration.

## Installing

You should install HatSploit to get Pwny, because Pwny depends on HatSploit Framework.

```
pip3 install git+https://github.com/EntySec/HatSploit
```

## Building Pwny

These are platforms which are supported by Pwny.

### macOS

* Dependencies: patched SDKs from [here](https://github.com/phracker/MacOSX-SDKs).

```shell
cmake -DSDK=<sdk> -B build; cd build; make
```

### Apple iOS

* Dependencies: patched SDKs from [here](https://github.com/theos/sdks).

```shell
cmake -DSDK=<sdk> -DIPHONE=ON -B build; cd build; make
```

### Linux

```shell
cmake -B build; cd build; make
```

**NOTE:** Specify `arch` if you want to cross-compile, but install compilers first. Example:

```shell
cmake -DARCH=<arch> -B build; cd build; make
```

### Windows

```shell
cmake -G "MinGW Makefiles" -B build; cd build; make
```

## Basic usage

To use Pwny and build payloads you should import it to your source.

```python3
from pwny import Pwny
from pwny.session import PwnySession
```

* `Pwny` - Pwny utilities, mostly for generating payloads and encoding arguments.
* `PwnySession` - Wrapper for `HatSploitSession` for Pwny, HatSploit should use it with Pwny payload.

To get Pwny executable, you should call `get_pwny()`.

```python3
from pwny import Pwny

pwny = Pwny()
executable = pwny.get_pwny('linux', 'x64')
```

To get Pwny phase, you should call `get_phase()`.

```python3
from pwny import Pwny

pwny = Pwny()
phase = pwny.get_phase('linux', 'x64')
```

## Adding Pwny payload

To add Pwny payload to HatSploit you should follow these steps.

* Write a basic HatSploit payload template.
* Import `Pwny` and `PwnySession` and put `Pwny` to `HatSploitPayload` class.
* Set payload parameter `Session` to `PwnySession`.
* Add `get_pwny()` with platform, architecture and config specified to the `run()`.

```python3
return self.get_pwny(
    self.details['Platform'],
    self.details['Architecture'],
    {
        'host': remote_host,
        'port': remote_port,
        'type': connection_type,
    }
)
```

* Add method `phase()` that will return shellcode that loads Pwny phase into the memory (see [Pwny Phase Stack](https://github.com/EntySec/Pwny/tree/main/docs/phase_stack.md)).
* Add method `implant()` and return `get_implant()` with platform and architecture from it.

You can find an example of implementing Pwny in the HatSploit Framework here - [Linux x64 Pwny Reverse TCP](https://github.com/EntySec/Pwny/blob/main/payload/linux/x64/pwny_reverse_tcp.py).

## Caveats

The code provided in this repository has not yet been prepared for use in a production environment. It can be improved anyways, so any contribution is welcome. Unfortunately, most part of the codebase is unstable due to the lack of testing. You can even experience memory leaks, so we'll be glad to accept every single PR which is fixing a potential issue.
