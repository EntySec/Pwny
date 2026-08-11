# Building Pwny from Source

This guide covers compiling Pwny's C implant, dependencies, and plugins for all supported platforms.

---

## Prerequisites

| Requirement | Purpose |
|-------------|---------|
| CMake >= 3.10 | Build system |
| Python 3.7+ | Python console |
| Make | Building dependencies |
| libtool | Library archiving |
| Cross-compiler toolchain | Target-specific (see below) |

---

## Build Process Overview

Building Pwny is a two-step process:

1. **Build dependencies** — third-party libraries compiled for the target
2. **Build Pwny** — the implant, plugins, and support binaries

```bash
# Step 1: Dependencies
make TARGET=<target-triple>

# Step 2: CMake build
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/<target>.cmake \
      -DMAIN=ON -B build
cmake --build build
```

---

## Dependencies

Pwny statically links these libraries:

| Library | Purpose |
|---------|---------|
| **libz** | Compression |
| **mbedTLS** | TLS/crypto (mbedtls, mbedx509, mbedcrypto) |
| **libcurl** | HTTP client |
| **libev** | Event loop |
| **libeio** | Async I/O |
| **SIGAR** | System info (CPU, memory, interfaces) |
| **libpawn** | Binary manipulation (non-iOS) |
| **libinjector** | Process injection (Linux) |

Dependencies are built per-target into `deps/build/<target>/`.

---

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `MAIN` | `OFF` | Build executable implant |
| `PLUGINS` | `OFF` | Build TAB plugins |
| `DEBUG` | `OFF` | Enable debug logging |
| `SHARED` | `OFF` | Build as shared library instead of static |
| `BUNDLE` | `OFF` | Build as macOS/iOS bundle |
| `SOURCE` | `src/main/main.c` | Custom executable source file |

---

## Platform-Specific Build Instructions

### Linux

See [Linux Build Guide](linux/README.md#building-for-linux) for detailed instructions.

**Quick summary:**

```bash
# Install cross-compilers
sudo bash scripts/cross.sh   # Downloads musl cross-compilers to /etc/cross/

# Build a single target
make TARGET=x86_64-linux-musl
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/x86_64-linux-musl.cmake \
      -DMAIN=ON -B build
cmake --build build
# Output: build/main (static-PIE ELF)

# Build ALL Linux targets and deploy templates
bash scripts/build-linux.sh
# Outputs: pwny/templates/<target>.exe and <target>.bin
```

Supported Linux targets:

| Target | Architecture |
|--------|-------------|
| `aarch64-linux-musl` | ARM 64-bit |
| `armv5l-linux-musleabi` | ARM 32-bit (v5) |
| `i486-linux-musl` | x86 32-bit |
| `x86_64-linux-musl` | x86 64-bit |
| `powerpc-linux-muslsf` | PowerPC 32-bit |
| `powerpc64le-linux-musl` | PowerPC 64-bit LE |
| `mips-linux-muslsf` | MIPS big-endian |
| `mipsel-linux-muslsf` | MIPS little-endian |
| `mips64-linux-musl` | MIPS 64-bit |
| `s390x-linux-musl` | IBM s390x |

### macOS

See [macOS Build Guide](macos/README.md#building-for-macos) for detailed instructions.

```bash
# Build dependencies (requires Xcode SDK)
make TARGET=aarch64-apple-darwin SDK=/path/to/MacOSX.sdk

# Build implant
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-apple-darwin.cmake \
      -DCMAKE_OSX_SYSROOT=/path/to/MacOSX.sdk \
      -DMAIN=ON -B build
cmake --build build
```

macOS targets:
- `x86_64-apple-darwin` — Intel Mac
- `aarch64-apple-darwin` — Apple Silicon

### iOS

See [iOS Build Guide](ios/README.md#building-for-ios) for detailed instructions.

```bash
# Build dependencies
make TARGET=aarch64-iphone-darwin SDK=/path/to/iPhoneOS.sdk

# Build as bundle
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-iphone-darwin.cmake \
      -DCMAKE_OSX_SYSROOT=/path/to/iPhoneOS.sdk \
      -DMAIN=ON -DBUNDLE=ON -B build
cmake --build build
```

iOS targets:
- `arm-iphone-darwin` — 32-bit ARM
- `aarch64-iphone-darwin` — 64-bit ARM

---

## Build Artifacts

After building, key files are:

| File | Description |
|------|-------------|
| `build/main` | Main implant binary |
| `build/plugins/` | Compiled plugin executables |
| `pwny/tabs/<platform>/<arch>/` | Deployed plugin binaries |
| `pwny/templates/<target>.exe` | Deployed implant templates |

---

## Deploying Templates

Built binaries are deployed to `pwny/templates/` for use by the Python payload generator:

```bash
# Manual deployment
cp build/main pwny/templates/x86_64-linux-musl.exe

# Linux: build-linux.sh does this automatically
bash scripts/build-linux.sh
```

The Python `Pwny` class looks up templates by target triple when generating payloads.

---

## Debug Builds

Enable debug mode for verbose logging:

```bash
cmake -DCMAKE_TOOLCHAIN_FILE=... -DMAIN=ON -DDEBUG=ON -B build
cmake --build build
```

Debug builds:
- Define the `DEBUG` preprocessor macro
- Enable verbose C2 logging
- Print TLV packet contents
- **Not suitable for production** — leaks operational information

---

## Compiler Flags

The build system applies security-conscious compiler flags:

| Flag | Purpose |
|------|---------|
| `-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=./` | Strip source paths from binaries |
| `-Os` | Optimize for size (plugins) |
| `-ffunction-sections -fdata-sections` | Enable dead-code elimination |
| `-Wl,--gc-sections` | Remove unused sections at link time |
| `-Wl,--strip-all` | Strip symbols |
| `-fno-stack-protector` | Disable stack canaries (plugins) |
| `-fno-asynchronous-unwind-tables` | Remove .eh_frame (plugins) |
| `-static-pie` | Position-independent static linking (Linux) |

---

## See Also

- [Plugin Development](plugin-development.md) — writing and building plugins
- Platform guides: [Linux](linux/), [macOS](macos/), [iOS](ios/)
